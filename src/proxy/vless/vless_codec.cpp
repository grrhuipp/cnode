#include "vless_codec.hpp"
#include "common/address_codec.hpp"
#include "common/buffer_util.hpp"
#include "common/byte_reader.hpp"

#include <array>
#include <cstring>
#include <limits>
#include <new>
#include <optional>

namespace vless {

namespace {

constexpr uint64_t kProtoWireLengthDelimited = 2;
constexpr uint64_t kProtoAddonsFlowField = 1;

bool ParseHeaderAddons(std::span<const uint8_t> data,
                       RequestHeader& request) {
    ByteReader reader(data);
    bool seen_flow = false;
    while (!reader.Empty()) {
        auto tag = reader.ReadVarintU64();
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
        auto flow_len = reader.ReadVarintU64();
        if (!flow_len || *flow_len == 0 || *flow_len > reader.Remaining()) {
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
    return 1 + VarintU64Size(flow.size()) + flow.size();
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
           writer.WriteVarintU64(flow.size()) &&
           writer.WriteString(flow);
}


struct PacketAddrHeader {
    TargetAddress target;
    size_t consumed = 0;
};

size_t EncodePacketAddrHeaderTo(const TargetAddress& target,
                                uint8_t* out,
                                size_t capacity) noexcept {
    if (!target.resolved_addr) {
        return 0;
    }
    if (target.resolved_addr->is_v4()) {
        if (capacity < 7) {
            return 0;
        }
        out[0] = 0x01;
        const auto bytes = target.resolved_addr->to_v4().to_bytes();
        std::memcpy(out + 1, bytes.data(), bytes.size());
        out[5] = static_cast<uint8_t>(target.port >> 8);
        out[6] = static_cast<uint8_t>(target.port);
        return 7;
    }
    if (target.resolved_addr->is_v6()) {
        if (capacity < 19) {
            return 0;
        }
        out[0] = 0x02;
        const auto bytes = target.resolved_addr->to_v6().to_bytes();
        std::memcpy(out + 1, bytes.data(), bytes.size());
        out[17] = static_cast<uint8_t>(target.port >> 8);
        out[18] = static_cast<uint8_t>(target.port);
        return 19;
    }
    return 0;
}

std::optional<PacketAddrHeader> DecodePacketAddrHeader(
    std::span<const uint8_t> data) noexcept {
    if (data.empty()) {
        return std::nullopt;
    }

    if (data[0] == 0x01) {
        if (data.size() < 7) {
            return std::nullopt;
        }
        net::ip::address_v4::bytes_type bytes{};
        std::memcpy(bytes.data(), data.data() + 1, bytes.size());
        const uint16_t port =
            (static_cast<uint16_t>(data[5]) << 8) |
            static_cast<uint16_t>(data[6]);
        return PacketAddrHeader{
            TargetAddress(net::ip::make_address_v4(bytes), port), 7};
    }

    if (data[0] == 0x02) {
        if (data.size() < 19) {
            return std::nullopt;
        }
        net::ip::address_v6::bytes_type bytes{};
        std::memcpy(bytes.data(), data.data() + 1, bytes.size());
        const uint16_t port =
            (static_cast<uint16_t>(data[17]) << 8) |
            static_cast<uint16_t>(data[18]);
        return PacketAddrHeader{
            TargetAddress(net::ip::make_address_v6(bytes), port), 19};
    }

    return std::nullopt;
}

size_t EncodeUdpHeaderTo(const TargetAddress& target,
                         bool packet_addr,
                         size_t payload_size,
                         std::span<uint8_t> out) noexcept {
    if (payload_size > std::numeric_limits<uint16_t>::max()) {
        return 0;
    }

    std::array<uint8_t, 19> address{};
    const size_t address_size = packet_addr
        ? EncodePacketAddrHeaderTo(target, address.data(), address.size())
        : 0;
    if (packet_addr && address_size == 0) {
        return 0;
    }
    if (address_size > std::numeric_limits<uint16_t>::max() - payload_size ||
        out.size() < address_size + 2) {
        return 0;
    }

    const size_t frame_payload_size = address_size + payload_size;
    out[0] = static_cast<uint8_t>(frame_payload_size >> 8);
    out[1] = static_cast<uint8_t>(frame_payload_size);
    if (address_size > 0) {
        std::memcpy(out.data() + 2, address.data(), address_size);
    }
    return address_size + 2;
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


bool IsPacketAddrMagic(const TargetAddress& target) noexcept {
    return target.IsDomain() && target.host == kPacketAddrMagicAddress;
}

void UdpFramer::Feed(buf::MultiBuffer input) {
    pending_.Append(std::move(input));
}

bool UdpFramer::Next(FramedUdpPacket& out) {
    out = {};
    buf::MultiBuffer payload;
    switch (pending_.Pop(payload)) {
    case buf::LengthPrefixedPacketBuffer::PopResult::NeedMore:
    case buf::LengthPrefixedPacketBuffer::PopResult::Finished:
        return false;
    case buf::LengthPrefixedPacketBuffer::PopResult::Invalid:
        throw IoSystemError(io_error::invalid_argument, "invalid VLESS UDP frame");
    case buf::LengthPrefixedPacketBuffer::PopResult::Packet:
        break;
    }
    if (packet_addr_) {
        std::array<uint8_t, 19> address{};
        const size_t copied = payload.CopyPrefixTo(address);
        auto header = DecodePacketAddrHeader(
            std::span<const uint8_t>(address.data(), copied));
        if (!header || !header->target.IsValid()) {
            pending_.Fail();
            throw IoSystemError(
                io_error::invalid_argument, "invalid VLESS packet address");
        }
        out.target = std::move(header->target);
        (void)payload.DropPrefixBytes(header->consumed);
    }
    out.payload = std::move(payload);
    return true;
}

void UdpFramer::Finish() {
    pending_.Finish();
}

net::awaitable<buf::MultiBuffer> UdpFramer::ReadDatagram(
    transport::MultiBufferReader& src,
    const TargetAddress& session_target) {
    if (pending_.Finished()) co_return buf::MultiBuffer{};
    for (;;) {
        FramedUdpPacket packet;
        if (Next(packet)) {
            const TargetAddress& target = packet.target
                ? *packet.target
                : session_target;
            if (!buf::SetUdpTarget(packet.payload, target)) {
                pending_.Fail();
                throw std::bad_alloc();
            }
            co_return std::move(packet.payload);
        }

        buf::MultiBuffer raw = co_await src.ReadMultiBuffer();
        if (raw.byte_size() == 0) {
            co_await ThrowIfCancelledOnEof();
            Finish();
            co_return buf::MultiBuffer{};
        }
        Feed(std::move(raw));
    }
}

net::awaitable<void> WriteUdpDatagram(
    transport::MultiBufferWriter& writer,
    buf::MultiBuffer payload,
    bool packet_addr,
    const TargetAddress* fixed_target) {
    const auto datagram = buf::InspectUdpDatagram(payload);
    if (datagram.status == buf::UdpDatagramStatus::Empty) {
        co_return;
    }
    if (!datagram.Valid() || !datagram.target || !datagram.target->IsValid()) {
        throw IoSystemError(
            io_error::invalid_argument,
            "VLESS UDP datagram contains missing or mixed endpoints");
    }
    if (!packet_addr && fixed_target &&
        !datagram.target->SameEndpoint(*fixed_target)) {
        throw IoSystemError(
            io_error::invalid_argument,
            "VLESS UDP datagram target differs from the fixed session target");
    }

    ConstBufferSpanBuilder<16> buffers;
    buffers.AppendMultiBuffer(payload);
    co_await WriteUdpDatagram(writer, *datagram.target, packet_addr, buffers.Span());
    payload.clear();
}

net::awaitable<void> WriteUdpDatagram(
    transport::MultiBufferWriter& writer,
    const TargetAddress& target,
    bool packet_addr,
    std::span<const net::const_buffer> payload) {
    const auto payload_size = buf::TrySumBufferSizes(
        payload, std::numeric_limits<uint16_t>::max());
    if (!payload_size) {
        throw IoSystemError(
            io_error::message_size, "VLESS UDP datagram is too large");
    }

    std::array<uint8_t, 32> header{};
    const size_t header_size = EncodeUdpHeaderTo(
        target, packet_addr, *payload_size, header);
    if (header_size == 0) {
        throw IoSystemError(
            io_error::message_size, "invalid VLESS UDP datagram size or target");
    }

    ConstBufferSpanBuilder<8> framed;
    framed.Append(net::buffer(header.data(), header_size));
    framed.AppendBuffers(payload);
    co_await writer.WriteBuffers(framed.Span());
}
}  // namespace vless
