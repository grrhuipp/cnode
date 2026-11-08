#include "udp_framing.hpp"

#include "common/buffer_util.hpp"

#include <array>
#include <cstring>
#include <limits>
#include <new>

namespace vless {

namespace {

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

        buf::MultiBuffer raw = co_await ReadMultiBufferOrThrowOnCancel(src);
        if (raw.byte_size() == 0) {
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

    std::array<uint8_t, 32> header{};
    const size_t header_size = EncodeUdpHeaderTo(
        *datagram.target, packet_addr, datagram.payload_size, header);
    if (header_size == 0) {
        throw IoSystemError(
            io_error::message_size, "invalid VLESS UDP datagram size or target");
    }

    ConstBufferSpanBuilder<1 + buf::MultiBuffer::kInlineCapacity> framed;
    framed.Append(net::buffer(header.data(), header_size));
    framed.AppendMultiBuffer(payload);
    co_await writer.WriteBuffers(framed.Span());
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
