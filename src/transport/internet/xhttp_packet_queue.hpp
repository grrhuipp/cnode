#pragma once

#include "acppnode/common/allocator.hpp"
#include "acppnode/common/buf/multi_buffer.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>
#include <utility>

namespace acpp::detail {

class XHttpPacketQueue final {
public:
    static constexpr size_t kMaxQueuedBytes = 4 * 1024 * 1024;
    static constexpr size_t kMaxQueuedPackets = 1024;

    [[nodiscard]] bool Push(uint64_t seq, buf::MultiBuffer payload) {
        if (seq < next_seq_) {
            payload.clear();
            return true;
        }
        if (seq > next_seq_ && pending_.contains(seq)) {
            payload.clear();
            return true;
        }

        const size_t bytes = buf::TotalLen(payload);
        if (queued_packets_ >= kMaxQueuedPackets ||
            bytes > kMaxQueuedBytes - queued_bytes_) {
            payload.clear();
            return false;
        }

        QueuedPacket packet{std::move(payload), bytes};
        if (seq == next_seq_) {
            ready_.push_back(std::move(packet));
            ++queued_packets_;
            queued_bytes_ += bytes;
            ++next_seq_;
            PromoteReadyPackets();
            return true;
        }

        pending_.emplace(seq, std::move(packet));
        ++queued_packets_;
        queued_bytes_ += bytes;
        return true;
    }

    [[nodiscard]] size_t ConsumePrefixTo(std::span<uint8_t> out) {
        PruneEmptyFront();
        if (ready_.empty() || out.empty()) {
            return 0;
        }
        auto& front = ready_.front();
        const size_t consumed = front.payload.ConsumePrefixTo(out);
        front.bytes -= std::min(front.bytes, consumed);
        queued_bytes_ -= std::min(queued_bytes_, consumed);
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
        queued_bytes_ -= std::min(queued_bytes_, packet.bytes);
        queued_packets_ -= std::min<size_t>(queued_packets_, 1);
        return std::move(packet.payload);
    }

    void Clear() noexcept {
        ready_.clear();
        pending_.clear();
        queued_bytes_ = 0;
        queued_packets_ = 0;
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
        while (!ready_.empty() && !buf::HasData(ready_.front().payload)) {
            queued_bytes_ -= std::min(queued_bytes_, ready_.front().bytes);
            queued_packets_ -= std::min<size_t>(queued_packets_, 1);
            ready_.pop_front();
        }
    }

    memory::ThreadLocalDeque<QueuedPacket> ready_;
    memory::ThreadLocalMap<uint64_t, QueuedPacket> pending_;
    size_t queued_bytes_ = 0;
    size_t queued_packets_ = 0;
    uint64_t next_seq_ = 0;
};

}  // namespace acpp::detail
