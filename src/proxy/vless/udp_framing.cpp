#include "udp_framing.hpp"

#include "acppnode/common/buffer_util.hpp"

#include <array>
#include <cstring>
#include <limits>
#include <new>

namespace acpp::vless {

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

bool EncodeUdpHeaderTo(const TargetAddress& target,
                       bool packet_addr,
                       size_t payload_size,
                       buf::Buffer& out) noexcept {
    if (payload_size == 0 || payload_size > std::numeric_limits<uint16_t>::max()) {
        return false;
    }

    std::array<uint8_t, 19> address{};
    const size_t address_size = packet_addr
        ? EncodePacketAddrHeaderTo(target, address.data(), address.size())
        : 0;
    if (packet_addr && address_size == 0) {
        return false;
    }
    if (address_size > std::numeric_limits<uint16_t>::max() - payload_size ||
        out.Available() < address_size + 2) {
        return false;
    }

    const size_t frame_payload_size = address_size + payload_size;
    auto tail = out.Tail();
    tail[0] = static_cast<uint8_t>(frame_payload_size >> 8);
    tail[1] = static_cast<uint8_t>(frame_payload_size);
    if (address_size > 0) {
        std::memcpy(tail.data() + 2, address.data(), address_size);
    }
    out.Produce(static_cast<uint32_t>(address_size + 2));
    return true;
}

}  // namespace

bool IsPacketAddrMagic(const TargetAddress& target) noexcept {
    return target.IsDomain() && target.host == kPacketAddrMagicAddress;
}

void UdpFramer::Feed(buf::MultiBuffer input) {
    if (failed_) {
        throw IoSystemError(io_error::invalid_argument, "failed VLESS UDP stream");
    }
    pending_.Append(std::move(input));
}

bool UdpFramer::Next(FramedUdpPacket& out) {
    if (failed_) {
        throw IoSystemError(io_error::invalid_argument, "failed VLESS UDP stream");
    }
    out = {};
    for (;;) {
        buf::MultiBuffer payload;
        const auto result = pending_.Pop(payload);
        if (result == buf::LengthPrefixedPacketBuffer::PopResult::NeedMore) {
            return false;
        }
        if (result == buf::LengthPrefixedPacketBuffer::PopResult::Invalid) {
            failed_ = true;
            throw IoSystemError(io_error::invalid_argument, "invalid VLESS UDP frame");
        }
        // Empty frames still consume their two-byte length prefix.
        if (payload.byte_size() == 0) continue;
        if (packet_addr_) {
            std::array<uint8_t, 19> address{};
            const size_t copied = payload.CopyPrefixTo(address);
            auto header = DecodePacketAddrHeader(
                std::span<const uint8_t>(address.data(), copied));
            if (!header || !header->target.IsValid()) {
                failed_ = true;
                pending_.Clear();
                throw IoSystemError(
                    io_error::invalid_argument, "invalid VLESS packet address");
            }
            out.target = std::move(header->target);
            (void)payload.DropPrefixBytes(header->consumed);
            if (payload.byte_size() == 0) continue;
        }
        out.payload = std::move(payload);
        return true;
    }
}

void UdpFramer::Finish() const {
    if (failed_) {
        throw IoSystemError(io_error::invalid_argument, "failed VLESS UDP stream");
    }
    pending_.Finish();
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

    buf::BufferGuard header{buf::Buffer::New()};
    if (!header) {
        throw std::bad_alloc();
    }
    if (!EncodeUdpHeaderTo(
            *datagram.target, packet_addr, datagram.payload_size, *header)) {
        throw IoSystemError(
            io_error::message_size, "invalid VLESS UDP datagram size or target");
    }

    for (buf::Buffer* buffer : payload) {
        if (buffer) {
            buffer->ClearUDP();
        }
    }
    buf::MultiBuffer framed{std::move(header)};
    payload.MoveTo(framed, true);
    co_await writer.WriteMultiBuffer(std::move(framed));
}

net::awaitable<void> WriteUdpDatagram(
    transport::MultiBufferWriter& writer,
    std::span<const net::const_buffer> payload) {
    co_await WriteUdpDatagram(writer, TargetAddress{}, false, payload);
}

net::awaitable<void> WriteUdpDatagram(
    transport::MultiBufferWriter& writer,
    const TargetAddress& target,
    bool packet_addr,
    std::span<const net::const_buffer> payload) {
    size_t payload_size = 0;
    for (const auto& buffer : payload) {
        if (buffer.size() >
            std::numeric_limits<uint16_t>::max() - payload_size) {
            throw IoSystemError(
                io_error::message_size, "VLESS UDP datagram is too large");
        }
        payload_size += buffer.size();
    }
    if (payload_size == 0) {
        co_return;
    }

    buf::BufferGuard header{buf::Buffer::New()};
    if (!header) {
        throw std::bad_alloc();
    }
    if (!EncodeUdpHeaderTo(target, packet_addr, payload_size, *header)) {
        throw IoSystemError(
            io_error::message_size, "invalid VLESS UDP datagram size or target");
    }

    ConstBufferSpanBuilder<8> framed;
    framed.Append(net::buffer(header->Bytes().data(), header->Bytes().size()));
    framed.AppendBuffers(payload);
    co_await writer.WriteBuffers(framed.Span());
}

}  // namespace acpp::vless
