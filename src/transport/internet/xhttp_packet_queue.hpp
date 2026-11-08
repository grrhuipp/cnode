#pragma once

#include "common/allocator.hpp"
#include "common/buf/multi_buffer.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>
#include <utility>

namespace detail {

class XHttpPacketQueue final {
public:
    static constexpr size_t kMaxQueuedBytes = 4 * 1024 * 1024;
    static constexpr size_t kInOrderHeadroomBytes = 64 * 1024;
    static constexpr size_t kMaxQueuedPackets = 1024;

    static constexpr size_t kMaxUploads = 64;

    [[nodiscard]] bool AcquireUpload() noexcept {
        if (uploads_ == kMaxUploads) return false;
        ++uploads_;
        return true;
    }
    void ReleaseUpload() noexcept { --uploads_; }
    [[nodiscard]] bool Reserve(size_t bytes) noexcept {
        if (bytes > kMaxQueuedBytes - queued_capacity_ - reserved_) return false;
        reserved_ += bytes;
        return true;
    }
    void Release(size_t bytes) noexcept { reserved_ -= bytes; }
    [[nodiscard]] size_t UsedCapacity() const noexcept {
        return queued_capacity_ + reserved_;
    }
    [[nodiscard]] bool Push(uint64_t seq, buf::MultiBuffer payload) {
        if (seq < next_seq_) {
            payload.clear();
            return true;
        }
        if (seq > next_seq_ && pending_.contains(seq)) {
            payload.clear();
            return true;
        }

        const size_t bytes = payload.byte_size();
        const size_t capacity = payload.size() * buf::Buffer::kSize;
        if (seq > next_seq_) {
            const size_t out_of_order_budget = kMaxQueuedBytes - kInOrderHeadroomBytes;
            if (seq - next_seq_ > kMaxQueuedPackets ||
                (bytes != 0 && pending_.size() >= kMaxQueuedPackets / 2) ||
                queued_bytes_ + bytes > out_of_order_budget ||
                queued_capacity_ + reserved_ + capacity > out_of_order_budget) {
                payload.clear();
                return false;
            }
        }
        const size_t packet_limit =
            (seq == next_seq_ && ready_.empty()) ? kMaxQueuedPackets + 1 : kMaxQueuedPackets;
        if (queued_packets_ >= packet_limit ||
            capacity > kMaxQueuedBytes - queued_capacity_ - reserved_) {
            payload.clear();
            return false;
        }

        QueuedPacket packet{std::move(payload), bytes};
        if (seq == next_seq_) {
            ready_.push_back(std::move(packet));
            ++queued_packets_;
            queued_bytes_ += bytes;
            queued_capacity_ += capacity;
            ++next_seq_;
            PromoteReadyPackets();
            return true;
        }

        pending_.emplace(seq, std::move(packet));
        ++queued_packets_;
        queued_bytes_ += bytes;
        queued_capacity_ += capacity;
        return true;
    }

    [[nodiscard]] size_t ConsumePrefixTo(std::span<uint8_t> out) {
        PruneEmptyFront();
        if (ready_.empty() || out.empty()) {
            return 0;
        }
        auto& front = ready_.front();
        const size_t old_blocks = front.payload.size();
        const size_t consumed = front.payload.ConsumePrefixTo(out);
        front.bytes -= std::min(front.bytes, consumed);
        queued_bytes_ -= std::min(queued_bytes_, consumed);
        queued_capacity_ -= (old_blocks - front.payload.size()) * buf::Buffer::kSize;
        PruneEmptyFront();
        return consumed;
    }

    [[nodiscard]] buf::MultiBuffer Pop() {
        PruneEmptyFront();
        if (ready_.empty()) {
            return {};
        }
        QueuedPacket packet = std::move(ready_.front());
        ready_.pop_front();
        queued_capacity_ -= packet.payload.size() * buf::Buffer::kSize;
        queued_bytes_ -= std::min(queued_bytes_, packet.bytes);
        queued_packets_ -= std::min<size_t>(queued_packets_, 1);
        return std::move(packet.payload);
    }

    void Clear() noexcept {
        ready_.clear();
        pending_.clear();
        queued_bytes_ = 0;
        queued_packets_ = 0;
        queued_capacity_ = 0;
    }

    [[nodiscard]] bool HasReady() {
        PruneEmptyFront();
        return !ready_.empty();
    }

    [[nodiscard]] size_t QueuedBytes() const noexcept { return queued_bytes_; }
    [[nodiscard]] size_t QueuedPackets() const noexcept { return queued_packets_; }

private:
    struct QueuedPacket {
        buf::MultiBuffer payload;
        size_t bytes = 0;
    };

    void PromoteReadyPackets() {
        while (true) {
            auto it = pending_.find(next_seq_);
            if (it == pending_.end()) {
                return;
            }
            ready_.push_back(std::move(it->second));
            pending_.erase(it);
            ++next_seq_;
        }
    }

    void PruneEmptyFront() {
        while (!ready_.empty() && ready_.front().payload.byte_size() == 0) {
            queued_bytes_ -= std::min(queued_bytes_, ready_.front().bytes);
            queued_capacity_ -= ready_.front().payload.size() * buf::Buffer::kSize;
            queued_packets_ -= std::min<size_t>(queued_packets_, 1);
            ready_.pop_front();
        }
    }

    memory::ThreadLocalDeque<QueuedPacket> ready_;
    memory::ThreadLocalMap<uint64_t, QueuedPacket> pending_;
    size_t queued_bytes_ = 0;
    size_t queued_packets_ = 0;
    size_t queued_capacity_ = 0;
    size_t reserved_ = 0;
    size_t uploads_ = 0;
    uint64_t next_seq_ = 0;
};

}  // namespace detail
