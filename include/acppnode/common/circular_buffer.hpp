#pragma once

// ============================================================================
// circular_buffer.hpp - 通用环形缓冲区
//
// 基于 vector 的环形缓冲区，替代 std::deque 减少内存分配次数。
// 用于 WebSocket 帧解码缓冲、协议解析暂存等场景。
// ============================================================================

#include "acppnode/common/allocator.hpp"

#include <vector>
#include <cstring>
#include <algorithm>

namespace acpp {

class CircularBuffer {
public:
    explicit CircularBuffer(size_t initial_capacity = 4096)
        : data_(initial_capacity), head_(0), size_(0) {}

    bool empty() const { return size_ == 0; }
    size_t size() const { return size_; }

    void push_back(const uint8_t* src, size_t len) {
        if (len == 0) return;
        ensure_capacity(size_ + len);

        size_t tail = (head_ + size_) % data_.size();
        size_t first_chunk = std::min(len, data_.size() - tail);
        std::memcpy(data_.data() + tail, src, first_chunk);
        if (first_chunk < len) {
            std::memcpy(data_.data(), src + first_chunk, len - first_chunk);
        }
        size_ += len;
    }

    void push_back(uint8_t byte) {
        push_back(&byte, 1);
    }

    size_t pop_front(uint8_t* dst, size_t max_len) {
        size_t copy = std::min(max_len, size_);
        if (copy == 0) return 0;

        size_t first_chunk = std::min(copy, data_.size() - head_);
        std::memcpy(dst, data_.data() + head_, first_chunk);
        if (first_chunk < copy) {
            std::memcpy(dst + first_chunk, data_.data(), copy - first_chunk);
        }

        head_ = (head_ + copy) % data_.size();
        size_ -= copy;

        // 如果完全清空，重置 head 以保持内存连续性
        if (size_ == 0) {
            head_ = 0;
        }
        return copy;
    }

    uint8_t pop_front_byte() {
        uint8_t b;
        pop_front(&b, 1);
        return b;
    }

    void clear() {
        head_ = 0;
        size_ = 0;
    }

    void ShrinkIfOversized(size_t keep_capacity) {
        if (size_ != 0 || data_.size() <= keep_capacity) {
            return;
        }

        data_ = memory::ByteVector(keep_capacity);
        head_ = 0;
    }

private:
    void ensure_capacity(size_t needed) {
        if (needed <= data_.size()) return;

        // 扩容为 2 倍或至少容纳 needed
        size_t new_cap = std::max(data_.size() * 2, needed);
        memory::ByteVector new_data(new_cap);

        // 线性化拷贝
        if (size_ > 0) {
            size_t first_chunk = std::min(size_, data_.size() - head_);
            std::memcpy(new_data.data(), data_.data() + head_, first_chunk);
            if (first_chunk < size_) {
                std::memcpy(new_data.data() + first_chunk, data_.data(), size_ - first_chunk);
            }
        }

        data_ = std::move(new_data);
        head_ = 0;
    }

    memory::ByteVector data_;
    size_t head_;
    size_t size_;
};

}  // namespace acpp
