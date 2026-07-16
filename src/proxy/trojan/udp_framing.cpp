#include "udp_framing.hpp"

#include "trojan_codec.hpp"
#include "acppnode/common/buffer_util.hpp"
#include "acppnode/common/container_util.hpp"

#include <cstring>
#include <limits>
#include <new>

namespace acpp::trojan {

namespace {

constexpr size_t kUdpFrameQueueShrinkItems = 64;

}  // namespace

void UdpFramer::Feed(const uint8_t* data, size_t len) {
    if (len == 0) {
        return;
    }
    if (!data) {
        throw IoSystemError(io_error::invalid_argument, "null Trojan UDP input");
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
        auto parsed = TrojanCodec::ParseUdpPacket(data, size);
        if (parsed.result == TrojanCodec::UdpParseResult::INCOMPLETE) {
            break;
        }
        if (parsed.result == TrojanCodec::UdpParseResult::INVALID ||
            !parsed.packet || parsed.consumed == 0) {
            ++pending_offset_;
            continue;
        }

        FramedUdpPacket packet;
        packet.target = parsed.packet->target;
        if (!parsed.packet->payload.empty() &&
            !buf::AppendSpanToMultiBuffer(parsed.packet->payload, packet.payload)) {
            throw std::bad_alloc();
        }
        pending_offset_ += parsed.consumed;
        if (!buf::HasData(packet.payload)) {
            continue;
        }
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
    buf::MultiBuffer payload) {
    const auto datagram = buf::InspectUdpDatagram(payload);
    if (datagram.status == buf::UdpDatagramStatus::Empty) {
        co_return;
    }
    if (!datagram.Valid() || !datagram.target->IsValid()) {
        throw IoSystemError(
            io_error::invalid_argument,
            "Trojan UDP datagram contains missing or mixed endpoints");
    }

    buf::BufferGuard header{buf::Buffer::New()};
    if (!header) {
        throw std::bad_alloc();
    }
    const size_t header_size = TrojanCodec::EncodeUdpPacketHeaderTo(
        *datagram.target,
        datagram.payload_size,
        header->Tail().data(),
        header->Available());
    if (header_size == 0) {
        throw IoSystemError(
            io_error::message_size, "invalid Trojan UDP datagram size or target");
    }
    header->Produce(static_cast<uint32_t>(header_size));

    buf::MultiBuffer framed{header.release()};
    payload.MoveTo(framed, true);
    co_await writer.WriteMultiBuffer(std::move(framed));
}

net::awaitable<void> WriteUdpDatagram(
    transport::MultiBufferWriter& writer,
    const TargetAddress& target,
    std::span<const net::const_buffer> payload) {
    size_t payload_size = 0;
    for (const auto& buffer : payload) {
        if (buffer.size() >
            std::numeric_limits<uint16_t>::max() - payload_size) {
            throw IoSystemError(
                io_error::message_size, "Trojan UDP datagram is too large");
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
    const size_t header_size = TrojanCodec::EncodeUdpPacketHeaderTo(
        target,
        payload_size,
        header->Tail().data(),
        header->Available());
    if (header_size == 0) {
        throw IoSystemError(
            io_error::invalid_argument, "invalid Trojan UDP target");
    }
    header->Produce(static_cast<uint32_t>(header_size));

    ConstBufferSpanBuilder<8> framed;
    framed.Append(net::buffer(header->Bytes()));
    framed.AppendBuffers(payload);
    co_await writer.WriteBuffers(framed.Span());
}

}  // namespace acpp::trojan
