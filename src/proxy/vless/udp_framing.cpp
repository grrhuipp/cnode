#include "udp_framing.hpp"

#include "vless_codec.hpp"
#include "acppnode/common/buffer_util.hpp"
#include "acppnode/common/container_util.hpp"

#include <array>
#include <cstring>
#include <limits>
#include <new>

namespace acpp::vless {

namespace {

constexpr size_t kUdpFrameQueueShrinkItems = 64;

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

void UdpFramer::Feed(const uint8_t* data, size_t len) {
    if (len == 0) {
        return;
    }
    if (!data) {
        throw IoSystemError(io_error::invalid_argument, "null VLESS UDP input");
    }

    CompactPending();
    pending_.insert(pending_.end(), data, data + len);
    Parse();
}

bool UdpFramer::Next(FramedUdpPacket& out) {
    if (queue_.empty()) {
        return false;
    }
    out = std::move(queue_.front());
    queue_.pop_front();
    if (queue_.empty() && shrink_queue_on_drain_) {
        TryShrinkSequence(queue_);
        shrink_queue_on_drain_ = false;
    }
    return true;
}

void UdpFramer::Parse() {
    while (pending_offset_ < pending_.size()) {
        const uint8_t* data = pending_.data() + pending_offset_;
        const size_t size = pending_.size() - pending_offset_;
        auto parsed = Codec::ParseUdpPacket(data, size);
        if (parsed.result == Codec::UdpParseResult::INCOMPLETE) {
            break;
        }
        if (parsed.result == Codec::UdpParseResult::INVALID ||
            !parsed.packet || parsed.consumed == 0) {
            ++pending_offset_;
            continue;
        }

        FramedUdpPacket packet;
        std::span<const uint8_t> payload = parsed.packet->payload;
        if (packet_addr_) {
            auto header = DecodePacketAddrHeader(payload);
            if (!header || header->consumed >= payload.size()) {
                pending_offset_ += parsed.consumed;
                continue;
            }
            packet.target = std::move(header->target);
            payload = payload.subspan(header->consumed);
        }
        if (!buf::AppendSpanToMultiBuffer(payload, packet.payload)) {
            throw std::bad_alloc();
        }
        pending_offset_ += parsed.consumed;
        queue_.push_back(std::move(packet));
        if (queue_.size() >= kUdpFrameQueueShrinkItems) {
            shrink_queue_on_drain_ = true;
        }
    }
    CompactPending();
}

void UdpFramer::CompactPending() {
    if (pending_offset_ == 0) {
        return;
    }
    if (pending_offset_ >= pending_.size()) {
        pending_.clear();
        pending_offset_ = 0;
        return;
    }
    if (pending_offset_ < buf::Buffer::kSize &&
        pending_offset_ * 2 < pending_.size()) {
        return;
    }
    pending_.erase(
        pending_.begin(),
        pending_.begin() + static_cast<std::ptrdiff_t>(pending_offset_));
    pending_offset_ = 0;
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
    buf::MultiBuffer framed{header.release()};
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
    framed.Append(net::buffer(header->Bytes()));
    framed.AppendBuffers(payload);
    co_await writer.WriteBuffers(framed.Span());
}

}  // namespace acpp::vless
