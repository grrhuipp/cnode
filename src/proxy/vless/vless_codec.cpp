#include "vless_codec.hpp"

#include "acppnode/common/byte_reader.hpp"
#include "acppnode/infra/log.hpp"

#include <array>
#include <cstring>
#include <limits>

namespace acpp::vless {

namespace {

constexpr uint64_t kProtoWireVarint = 0;
constexpr uint64_t kProtoWireFixed64 = 1;
constexpr uint64_t kProtoWireLengthDelimited = 2;
constexpr uint64_t kProtoWireFixed32 = 5;
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

bool SkipProtoField(ByteReader& reader, uint64_t wire_type) noexcept {
    switch (wire_type) {
    case kProtoWireVarint:
        return ReadProtoVarint(reader).has_value();
    case kProtoWireFixed64:
        return reader.Skip(8);
    case kProtoWireLengthDelimited: {
        auto len = ReadProtoVarint(reader);
        if (!len || *len > reader.Remaining()) {
            return false;
        }
        return reader.Skip(static_cast<size_t>(*len));
    }
    case kProtoWireFixed32:
        return reader.Skip(4);
    default:
        return false;
    }
}

bool ParseHeaderAddons(std::span<const uint8_t> data,
                       RequestHeader& request) {
    ByteReader reader(data);
    while (!reader.Empty()) {
        auto tag = ReadProtoVarint(reader);
        if (!tag || *tag == 0) {
            return false;
        }
        const uint64_t field_number = *tag >> 3;
        const uint64_t wire_type = *tag & 0x07;
        if (field_number == kProtoAddonsFlowField &&
            wire_type == kProtoWireLengthDelimited) {
            auto flow_len = ReadProtoVarint(reader);
            if (!flow_len || *flow_len > reader.Remaining()) {
                return false;
            }
            const auto flow = reader.ReadStringView(static_cast<size_t>(*flow_len));
            if (!reader.Ok()) {
                return false;
            }
            request.flow.assign(flow.data(), flow.size());
            continue;
        }
        if (!SkipProtoField(reader, wire_type)) {
            return false;
        }
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

std::optional<TargetAddress> ReadAddress(ByteReader& reader) {
    const uint16_t port = reader.ReadU16BE();
    const uint8_t atype = reader.ReadU8();
    if (!reader.Ok()) {
        return std::nullopt;
    }

    if (atype == 0x01) {
        auto ipv4_bytes = reader.ReadBytes(4);
        if (!reader.Ok()) return std::nullopt;

        net::ip::address_v4::bytes_type bytes{};
        std::memcpy(bytes.data(), ipv4_bytes.data(), bytes.size());
        return TargetAddress(net::ip::make_address_v4(bytes), port);
    }

    if (atype == 0x02) {
        const uint8_t domain_len = reader.ReadU8();
        if (!reader.Ok() || domain_len == 0 || domain_len > 253) {
            return std::nullopt;
        }
        const std::string_view domain = reader.ReadStringView(domain_len);
        if (!reader.Ok()) return std::nullopt;
        return TargetAddress(domain, port);
    }

    if (atype == 0x03) {
        auto ipv6_bytes = reader.ReadBytes(16);
        if (!reader.Ok()) return std::nullopt;

        net::ip::address_v6::bytes_type bytes{};
        std::memcpy(bytes.data(), ipv6_bytes.data(), bytes.size());
        return TargetAddress(net::ip::make_address_v6(bytes), port);
    }

    return std::nullopt;
}

size_t VlessAddressSize(const TargetAddress& target) {
    if (target.IsDomain()) {
        return target.host.size() <= 253 ? 1 + 1 + target.host.size() : 0;
    }

    if (target.resolved_addr) {
        if (target.resolved_addr->is_v4()) return 1 + 4;
        if (target.resolved_addr->is_v6()) return 1 + 16;
    }

    return 0;
}

bool WriteAddress(ByteWriter& writer, const TargetAddress& target) {
    writer.WriteU16BE(target.port);
    if (target.IsDomain()) {
        if (target.host.empty() || target.host.size() > 253) {
            return false;
        }
        writer.WriteU8(0x02);
        writer.WriteU8(static_cast<uint8_t>(target.host.size()));
        writer.WriteString(target.host);
        return writer.Ok();
    }

    if (target.resolved_addr && target.resolved_addr->is_v4()) {
        writer.WriteU8(0x01);
        auto bytes = target.resolved_addr->to_v4().to_bytes();
        writer.WriteBytes(bytes.data(), bytes.size());
        return writer.Ok();
    }

    if (target.resolved_addr && target.resolved_addr->is_v6()) {
        writer.WriteU8(0x03);
        auto bytes = target.resolved_addr->to_v6().to_bytes();
        writer.WriteBytes(bytes.data(), bytes.size());
        return writer.Ok();
    }

    return false;
}

}  // namespace

std::optional<RequestHeader> Codec::ParseRequestHeader(
    const uint8_t* data,
    size_t len,
    size_t& consumed) {
    consumed = 0;
    if (len < 1 + 16 + 1 + 1 + 2 + 1) {
        return std::nullopt;
    }

    ByteReader reader(data, len);
    RequestHeader req;
    req.version = reader.ReadU8();
    if (req.version != kVersion) {
        return std::nullopt;
    }

    const auto uuid = reader.ReadBytes(16);
    if (!reader.Ok()) return std::nullopt;
    std::memcpy(req.uuid.data(), uuid.data(), req.uuid.size());

    req.addons_len = reader.ReadU8();
    auto addons = reader.ReadBytes(req.addons_len);
    if (!reader.Ok()) {
        return std::nullopt;
    }
    if (!ParseHeaderAddons(addons, req)) {
        return std::nullopt;
    }

    const uint8_t command = reader.ReadU8();
    req.command = static_cast<Command>(command);
    if (req.command != Command::TCP &&
        req.command != Command::UDP &&
        req.command != Command::MUX) {
        return std::nullopt;
    }

    if (req.command == Command::MUX) {
        req.target = TargetAddress("v1.mux.cool", 9527);
        consumed = reader.Position();
        return req;
    }

    auto target = ReadAddress(reader);
    if (!target) {
        return std::nullopt;
    }
    req.target = std::move(*target);

    consumed = reader.Position();
    return req;
}

size_t Codec::EncodeRequestHeaderTo(
    const std::array<uint8_t, 16>& uuid,
    Command command,
    const TargetAddress& target,
    uint8_t* output,
    size_t output_size,
    std::string_view flow) {
    const size_t addons_len = EncodedAddonsSize(flow);
    if (addons_len > std::numeric_limits<uint8_t>::max()) {
        return 0;
    }
    const size_t addr_size = command == Command::MUX ? 0 : VlessAddressSize(target);
    if (addr_size == 0) {
        if (command == Command::MUX) {
            const size_t total = 1 + uuid.size() + 1 + addons_len + 1;
            if (total > output_size) {
                return 0;
            }
            ByteWriter writer(output, output_size);
            writer.WriteU8(kVersion);
            writer.WriteBytes(uuid.data(), uuid.size());
            if (!WriteHeaderAddons(writer, flow)) {
                return 0;
            }
            writer.WriteU8(static_cast<uint8_t>(command));
            return writer.Ok() ? writer.Position() : 0;
        }
        return 0;
    }

    const size_t total = 1 + uuid.size() + 1 + addons_len + 1 + 2 + addr_size;
    if (total > output_size) {
        return 0;
    }

    ByteWriter writer(output, output_size);
    writer.WriteU8(kVersion);
    writer.WriteBytes(uuid.data(), uuid.size());
    if (!WriteHeaderAddons(writer, flow)) {
        return 0;
    }
    writer.WriteU8(static_cast<uint8_t>(command));
    if (!WriteAddress(writer, target)) {
        return 0;
    }
    return writer.Ok() ? writer.Position() : 0;
}

size_t Codec::EncodeResponseHeaderTo(uint8_t* output,
                                     size_t output_size) noexcept {
    if (output_size < 2) {
        return 0;
    }
    output[0] = kVersion;
    output[1] = 0;
    return 2;
}

std::optional<size_t> Codec::ParseResponseHeader(
    const uint8_t* data,
    size_t len,
    size_t& consumed) noexcept {
    consumed = 0;
    if (len < 2) {
        return std::nullopt;
    }
    if (data[0] != kVersion) {
        return std::nullopt;
    }
    const size_t addons_len = data[1];
    if (len < 2 + addons_len) {
        return std::nullopt;
    }
    consumed = 2 + addons_len;
    return consumed;
}

size_t Codec::EncodeUdpPacketTo(const uint8_t* payload,
                                size_t payload_len,
                                uint8_t* output,
                                size_t output_size) noexcept {
    if (payload_len == 0 || payload_len > 0xFFFF || output_size < payload_len + 2) {
        return 0;
    }
    output[0] = static_cast<uint8_t>((payload_len >> 8) & 0xFF);
    output[1] = static_cast<uint8_t>(payload_len & 0xFF);
    std::memcpy(output + 2, payload, payload_len);
    return payload_len + 2;
}

Codec::UdpParseOutput Codec::ParseUdpPacket(const uint8_t* data,
                                            size_t len) noexcept {
    UdpParseOutput out;
    if (len < 2) {
        out.result = UdpParseResult::INCOMPLETE;
        return out;
    }
    const size_t payload_len =
        (static_cast<size_t>(data[0]) << 8) | static_cast<size_t>(data[1]);
    if (payload_len == 0) {
        out.result = UdpParseResult::INVALID;
        return out;
    }
    if (len < payload_len + 2) {
        out.result = UdpParseResult::INCOMPLETE;
        return out;
    }
    out.result = UdpParseResult::SUCCESS;
    out.packet = UdpPacket{std::span<const uint8_t>{data + 2, payload_len}};
    out.consumed = payload_len + 2;
    return out;
}

}  // namespace acpp::vless
