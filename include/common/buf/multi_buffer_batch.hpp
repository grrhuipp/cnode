#pragma once

#include "common/buf/multi_buffer.hpp"

namespace buf {

// Each element owns one reader result, including all fragments of one datagram.
// The common zero/one-element case needs no queue allocation.
class MultiBufferBatch {
public:
    MultiBufferBatch() noexcept = default;
    explicit MultiBufferBatch(MultiBuffer payload) { Push(std::move(payload)); }
    MultiBufferBatch(const MultiBufferBatch&) = delete;
    MultiBufferBatch& operator=(const MultiBufferBatch&) = delete;

    MultiBufferBatch(MultiBufferBatch&& other) noexcept
        : first_(std::move(other.first_)), overflow_(std::move(other.overflow_)),
          bytes_(std::exchange(other.bytes_, 0)),
          occupied_(std::exchange(other.occupied_, false)) {}

    MultiBufferBatch& operator=(MultiBufferBatch&& other) noexcept {
        if (this != &other) {
            clear();
            overflow_ = std::move(other.overflow_);
            first_ = std::move(other.first_);
            bytes_ = std::exchange(other.bytes_, 0);
            occupied_ = std::exchange(other.occupied_, false);
        }
        return *this;
    }

    void Push(MultiBuffer payload) {
        const size_t bytes = payload.byte_size();
        if (bytes == 0 && !payload.HasUDP()) {
            payload.clear();
            return;
        }
        if (bytes > std::numeric_limits<size_t>::max() - bytes_) {
            throw std::length_error("MultiBufferBatch byte size overflow");
        }
        if (!occupied_) {
            first_ = std::move(payload);
            occupied_ = true;
        } else {
            overflow_.push_back(std::move(payload));
        }
        bytes_ += bytes;
    }

    [[nodiscard]] MultiBuffer PopFront() noexcept {
        if (!occupied_) return {};
        MultiBuffer result = std::move(first_);
        bytes_ -= result.byte_size();
        if (!overflow_.empty()) {
            first_ = std::move(overflow_.front());
            overflow_.pop_front();
        } else {
            occupied_ = false;
        }
        return result;
    }

    [[nodiscard]] bool empty() const noexcept { return !occupied_; }
    [[nodiscard]] size_t byte_size() const noexcept { return bytes_; }

    void clear() noexcept {
        first_.clear();
        overflow_.clear();
        bytes_ = 0;
        occupied_ = false;
    }

private:
    MultiBuffer first_;
    memory::ThreadLocalDeque<MultiBuffer> overflow_;
    size_t bytes_ = 0;
    bool occupied_ = false;
};

} // namespace buf
