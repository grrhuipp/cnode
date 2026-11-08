#include "vless_codec.hpp"
#include "udp_framing.hpp"
#include "common/address_codec.hpp"

#include "common/byte_reader.hpp"

#include <array>
#include <cstring>
#include <limits>
#include <optional>

namespace vless {

namespace {

constexpr uint64_t kProtoWireLengthDelimited = 2;
constexpr uint64_t kProtoAddonsFlowField = 1;

std::optional<uint64_t> ReadProtoVarint(ByteReader& reader) noexcept {
    uint64_t value = 0;
    uint8_t shift = 0;
    for (size_t i = 0; i < 10; ++i) {
        const uint8_t byte = reader.ReadU8();
        if (!reader.Ok()) {
            return std::nullopt;
        }
        if (shift == 63 && (byte & 0xFE) != 0) {
            return std::nullopt;
        }
        value |= static_cast<uint64_t>(byte & 0x7F) << shift;
        if ((byte & 0x80) == 0) {
            return value;
        }
        shift += 7;
    }
    return std::nullopt;
}

bool WriteProtoVarint(ByteWriter& writer, size_t value) noexcept {
    while (value >= 0x80) {
        if (!writer.WriteU8(static_cast<uint8_t>((value & 0x7F) | 0x80))) {
            return false;
        }
        value >>= 7;
    }
    return writer.WriteU8(static_cast<uint8_t>(value));
}

size_t ProtoVarintSize(size_t value) noexcept {
    size_t size = 1;
    while (value >= 0x80) {
        value >>= 7;
        ++size;
    }
    return size;
}

bool ParseHeaderAddons(std::span<const uint8_t> data,
                       RequestHeader& request) {
    ByteReader reader(data);
    bool seen_flow = false;
    while (!reader.Empty()) {
        auto tag = ReadProtoVarint(reader);
        if (!tag || *tag == 0) {
            return false;
        }
        const uint64_t field_number = *tag >> 3;
        const uint64_t wire_type = *tag & 0x07;
        if (field_number != kProtoAddonsFlowField ||
            wire_type != kProtoWireLengthDelimited ||
            seen_flow) {
            return false;
        }
        auto flow_len = ReadProtoVarint(reader);
        if (!flow_len || *flow_len > reader.Remaining()) {
            return false;
        }
        const auto flow = reader.ReadStringView(static_cast<size_t>(*flow_len));
        if (!reader.Ok()) {
            return false;
        }
        request.flow.assign(flow.data(), flow.size());
        seen_flow = true;
    }
    return reader.Ok();
}

size_t EncodedAddonsSize(std::string_view flow) noexcept {
    if (flow.empty()) {
        return 0;
    }
    return 1 + ProtoVarintSize(flow.size()) + flow.size();
}

bool WriteHeaderAddons(ByteWriter& writer, std::string_view flow) noexcept {
    const size_t addons_len = EncodedAddonsSize(flow);
    if (addons_len > std::numeric_limits<uint8_t>::max()) {
        return false;
    }
    if (!writer.WriteU8(static_cast<uint8_t>(addons_len))) {
        return false;
    }
    if (addons_len == 0) {
        return true;
    }
    constexpr uint8_t flow_tag =
        static_cast<uint8_t>((kProtoAddonsFlowField << 3) | kProtoWireLengthDelimited);
    return writer.WriteU8(flow_tag) &&
           WriteProtoVarint(writer, flow.size()) &&
           writer.WriteString(flow);
}

}  // namespace

RequestHeaderDecodeResult DecodeRequestHeader(std::span<const uint8_t> data) {
    constexpr size_t kUuidOffset = 1;
    constexpr size_t kAddonsLenOffset = kUuidOffset + 16;
    RequestHeaderDecodeResult result;
    if (data.empty()) {
        result.required = 1;
        return result;
    }
    if (data[0] != kVersion) {
        result.status = RequestHeaderDecodeStatus::InvalidVersion;
        return result;
    }
    if (data.size() <= kAddonsLenOffset) {
        result.required = kAddonsLenOffset + 2;
        return result;
    }
    const uint8_t addons_len = data[kAddonsLenOffset];
    const size_t command_offset = kAddonsLenOffset + 1 + addons_len;
    if (data.size() <= command_offset) {
        result.required = command_offset + 1;
        return result;
    }

    RequestHeader& header = result.header;
    const uint8_t command = data[command_offset];
    size_t consumed = command_offset + 1;
    if (command == static_cast<uint8_t>(Command::MUX)) {
        header.target = TargetAddress("v1.mux.cool", 9527);
    } else if (command == static_cast<uint8_t>(Command::TCP) ||
               command == static_cast<uint8_t>(Command::UDP)) {
        auto address = DecodeAddress(
            data.subspan(consumed), AddressWireFormat::PortFirst,
            {.require_non_empty_domain = true, .allow_metadata = true});
        if (address.status == AddressDecodeStatus::Invalid) {
            result.status = RequestHeaderDecodeStatus::InvalidAddress;
            return result;
        }
        if (address.status == AddressDecodeStatus::Incomplete) {
            result.required = consumed + address.required;
            return result;
        }
        header.target = std::move(address.target);
        header.forwarded = std::move(address.forwarded);
        if (!header.target.IsValid() &&
            !(command == static_cast<uint8_t>(Command::UDP) &&
              IsPacketAddrMagic(header.target))) {
            result.status = RequestHeaderDecodeStatus::InvalidAddress;
            return result;
        }
        consumed += address.consumed;
    } else {
        result.status = RequestHeaderDecodeStatus::InvalidCommand;
        return result;
    }

    header.command = static_cast<Command>(command);
    std::memcpy(header.uuid.data(), data.data() + kUuidOffset, header.uuid.size());
    header.addons_len = addons_len;
    if (!ParseHeaderAddons(data.subspan(kAddonsLenOffset + 1, addons_len), header)) {
        result.status = RequestHeaderDecodeStatus::InvalidAddons;
        return result;
    }
    result.status = RequestHeaderDecodeStatus::Complete;
    result.consumed = consumed;
    return result;
}

size_t EncodeRequestHeaderTo(
    const std::array<uint8_t, 16>& uuid,
    Command command,
    const TargetAddress& target,
    uint8_t* output,
    size_t output_size,
    std::string_view flow,
    ForwardedMetadataView forwarded) {
    const size_t addons_len = EncodedAddonsSize(flow);
    if (addons_len > std::numeric_limits<uint8_t>::max()) {
        return 0;
    }
    size_t address_size = 0;
    if (command != Command::MUX) {
        if (target.IsDomain() && (target.host.empty() || target.host.size() > 253)) {
            return 0;
        }
        address_size = AddressEncodedSize(target, forwarded);
        if (address_size == 0) {
            return 0;
        }
    }
    if (1 + uuid.size() + 1 + addons_len + 1 + address_size > output_size) {
        return 0;
    }

    ByteWriter writer(output, output_size);
    writer.WriteU8(kVersion);
    writer.WriteBytes(uuid.data(), uuid.size());
    if (!WriteHeaderAddons(writer, flow)) {
        return 0;
    }
    writer.WriteU8(static_cast<uint8_t>(command));
    if (!writer.Ok()) {
        return 0;
    }
    if (command == Command::MUX) {
        return writer.Position();
    }
    const size_t encoded = EncodeAddressTo(target, output + writer.Position(),
        output_size - writer.Position(), AddressWireFormat::PortFirst, forwarded);
    return encoded == 0 ? 0 : writer.Position() + encoded;
}

}  // namespace vless
