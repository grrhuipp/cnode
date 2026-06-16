#pragma once

#include "acppnode/common/allocator.hpp"
#include "acppnode/common/buffer_util.hpp"
#include "acppnode/common/buf/multi_buffer.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iterator>
#include <memory>
#include <span>

namespace acpp {

class InitialPayload {
public:
    // Keep the always-present coroutine-frame footprint small. Larger early
    // payloads use the Worker heap and are handed to first-packet relay once.
    static constexpr size_t kInlineSize = 256;

    InitialPayload() = default;
    ~InitialPayload() noexcept = default;

    InitialPayload(const InitialPayload& other) {
        if (other.overflow_.empty()) {
            size_ = other.size_;
            std::copy_n(other.inline_.begin(), other.size_, inline_.begin());
            return;
        }
        AppendBuffers(other.overflow_);
    }

    InitialPayload& operator=(const InitialPayload& other) {
        if (this == &other) {
            return *this;
        }
        clear();
        if (other.overflow_.empty()) {
            size_ = other.size_;
            std::copy_n(other.inline_.begin(), other.size_, inline_.begin());
            return *this;
        }
        AppendBuffers(other.overflow_);
        return *this;
    }

    InitialPayload(InitialPayload&& other) noexcept
        : overflow_(std::move(other.overflow_))
        , size_(other.size_) {
        if (overflow_.empty()) {
            std::copy_n(other.inline_.begin(), other.size_, inline_.begin());
        }
        other.size_ = 0;
    }

    InitialPayload& operator=(InitialPayload&& other) noexcept {
        if (this == &other) {
            return *this;
        }
        clear();
        size_ = other.size_;
        overflow_ = std::move(other.overflow_);
        if (overflow_.empty()) {
            std::copy_n(other.inline_.begin(), other.size_, inline_.begin());
        }
        other.size_ = 0;
        return *this;
    }

    [[nodiscard]] bool empty() const noexcept { return size_ == 0; }
    [[nodiscard]] size_t size() const noexcept { return size_; }
    [[nodiscard]] const uint8_t* data() const noexcept {
        return overflow_.empty() ? inline_.data() : nullptr;
    }
    [[nodiscard]] std::span<const uint8_t> span() const noexcept {
        return overflow_.empty()
            ? std::span<const uint8_t>{inline_.data(), size_}
            : std::span<const uint8_t>{};
    }
    [[nodiscard]] bool IsContiguous() const noexcept {
        return overflow_.empty();
    }
    [[nodiscard]] size_t CopyTo(uint8_t* out, size_t out_size) const {
        if (!out || out_size < size_) {
            return 0;
        }
        if (overflow_.empty()) {
            std::memcpy(out, inline_.data(), size_);
            return size_;
        }
        size_t offset = 0;
        for (const auto* buffer : overflow_) {
            if (!buffer || buffer->IsEmpty()) {
                continue;
            }
            const auto bytes = buffer->Bytes();
            std::memcpy(out + offset, bytes.data(), bytes.size());
            offset += bytes.size();
        }
        return offset;
    }
    // 复制最多 out_size 字节的前缀到 out，返回实际复制量。用于嗅探：只需首部
    // 若干字节即可解析 TLS ClientHello SNI / HTTP Host，无需拷贝整个首包。
    [[nodiscard]] size_t CopyPrefixTo(uint8_t* out, size_t out_size) const {
        if (!out || out_size == 0) {
            return 0;
        }
        const size_t want = std::min(out_size, size_);
        if (overflow_.empty()) {
            std::memcpy(out, inline_.data(), want);
            return want;
        }
        size_t offset = 0;
        for (const auto* buffer : overflow_) {
            if (offset >= want) {
                break;
            }
            if (!buffer || buffer->IsEmpty()) {
                continue;
            }
            const auto bytes = buffer->Bytes();
            const size_t n = std::min(bytes.size(), want - offset);
            std::memcpy(out + offset, bytes.data(), n);
            offset += n;
        }
        return offset;
    }

    [[nodiscard]] buf::MultiBuffer MoveToMultiBuffer() {
        if (!overflow_.empty()) {
            size_ = 0;
            return std::move(overflow_);
        }
        buf::MultiBuffer mb;
        (void)buf::AppendSpanToMultiBuffer(span(), mb);
        size_ = 0;
        return mb;
    }

    void clear() noexcept {
        size_ = 0;
        overflow_.clear();
    }

    template <typename It>
    void assign(It first, It last) {
        const size_t len = static_cast<size_t>(std::distance(first, last));
        clear();
        if (len <= inline_.size()) {
            std::copy(first, last, inline_.begin());
            size_ = len;
            return;
        }
        size_t written = 0;
        while (first != last) {
            buf::BufferGuard buffer{buf::Buffer::New()};
            if (!buffer) {
                throw std::bad_alloc();
            }
            while (first != last && buffer->Available() > 0) {
                buffer->Tail().front() = static_cast<uint8_t>(*first);
                buffer->Produce(1);
                ++first;
                ++written;
            }
            overflow_.push_back(buffer.release());
        }
        size_ = written;
    }

    void append(const uint8_t* data, size_t len) {
        if (!data || len == 0) {
            return;
        }
        const size_t old_size = size_;
        const size_t new_size = old_size + len;
        if (new_size <= inline_.size() && overflow_.empty()) {
            std::memcpy(inline_.data() + old_size, data, len);
            size_ = new_size;
            return;
        }

        if (overflow_.empty() && old_size > 0) {
            (void)buf::AppendSpanToMultiBuffer({inline_.data(), old_size}, overflow_);
        }
        (void)buf::AppendSpanToMultiBuffer({data, len}, overflow_);
        size_ = new_size;
    }

private:
    void AppendBuffers(const buf::MultiBuffer& buffers) {
        for (const auto* buffer : buffers) {
            if (!buffer || buffer->IsEmpty()) {
                continue;
            }
            const auto bytes = buffer->Bytes();
            append(bytes.data(), bytes.size());
        }
    }

    std::array<uint8_t, kInlineSize> inline_{};
    buf::MultiBuffer overflow_;
    size_t size_ = 0;
};

}  // namespace acpp
