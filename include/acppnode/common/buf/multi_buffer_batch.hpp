#pragma once

#include "acppnode/common/buf/multi_buffer.hpp"

namespace acpp::buf {

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
          cursor_(std::exchange(other.cursor_, 0)),
          bytes_(std::exchange(other.bytes_, 0)),
          occupied_(std::exchange(other.occupied_, false)) {}

    MultiBufferBatch& operator=(MultiBufferBatch&& other) {
        if (this != &other) {
            clear();
            overflow_ = std::move(other.overflow_);
            first_ = std::move(other.first_);
            cursor_ = std::exchange(other.cursor_, 0);
            bytes_ = std::exchange(other.bytes_, 0);
            occupied_ = std::exchange(other.occupied_, false);
        }
        return *this;
    }

    void Push(MultiBuffer payload) {
        if (payload.empty()) return;
        const size_t bytes = payload.byte_size();
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
        if (cursor_ < overflow_.size()) {
            first_ = std::move(overflow_[cursor_++]);
            if (cursor_ == overflow_.size()) ReleaseOverflow();
        } else {
            occupied_ = false;
        }
        return result;
    }

    [[nodiscard]] bool empty() const noexcept { return !occupied_; }
    [[nodiscard]] size_t byte_size() const noexcept { return bytes_; }

    void clear() noexcept {
        first_.clear();
        ReleaseOverflow();
        bytes_ = 0;
        occupied_ = false;
    }

private:
    void ReleaseOverflow() noexcept {
        memory::ThreadLocalVector<MultiBuffer> empty(overflow_.get_allocator());
        overflow_.swap(empty);
        cursor_ = 0;
    }

    MultiBuffer first_;
    memory::ThreadLocalVector<MultiBuffer> overflow_;
    size_t cursor_ = 0;
    size_t bytes_ = 0;
    bool occupied_ = false;
};

} // namespace acpp::buf
