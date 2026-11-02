#pragma once

#include "acppnode/common/buf/multi_buffer.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <utility>
#include <span>

namespace acpp {

class InitialPayload {
public:
    // Keep the always-present coroutine-frame footprint small. Larger early
    // payloads use the Worker heap and are transferred into the ordinary relay loop once.
    static constexpr size_t kInlineSize = 256;

    InitialPayload() = default;
    explicit InitialPayload(buf::MultiBuffer data) noexcept : overflow_(std::move(data)) {}
    ~InitialPayload() noexcept = default;

    InitialPayload(const InitialPayload&) = delete;
    InitialPayload& operator=(const InitialPayload&) = delete;

    InitialPayload(InitialPayload&& other) noexcept
        : overflow_(std::move(other.overflow_))
        , inline_size_(std::exchange(other.inline_size_, 0)) {
        std::copy_n(other.inline_.begin(), inline_size_, inline_.begin());
    }

    InitialPayload& operator=(InitialPayload&& other) noexcept {
        if (this != &other) {
            overflow_ = std::move(other.overflow_);
            inline_size_ = std::exchange(other.inline_size_, 0);
            std::copy_n(other.inline_.begin(), inline_size_, inline_.begin());
        }
        return *this;
    }

    [[nodiscard]] bool empty() const noexcept { return size() == 0; }
    [[nodiscard]] size_t size() const noexcept { return overflow_.empty() ? inline_size_ : overflow_.byte_size(); }
    [[nodiscard]] std::span<const uint8_t> span() const noexcept {
        return overflow_.empty()
            ? std::span<const uint8_t>{inline_.data(), inline_size_}
            : std::span<const uint8_t>{};
    }
    [[nodiscard]] bool IsContiguous() const noexcept {
        return overflow_.empty();
    }
    [[nodiscard]] std::span<const uint8_t> PrefixSpan(size_t len) const noexcept {
        if (len == 0 || len > size()) {
            return {};
        }
        if (overflow_.empty()) {
            return std::span<const uint8_t>(inline_.data(), len);
        }
        for (const auto* buffer : overflow_) {
            if (!buffer || buffer->IsEmpty()) {
                continue;
            }
            const auto bytes = buffer->Bytes();
            if (bytes.size() >= len) {
                return bytes.first(len);
            }
            return {};
        }
        return {};
    }
    // 复制最多 out_size 字节的前缀到 out，返回实际复制量。用于嗅探：只需首部
    // 若干字节即可解析 TLS ClientHello SNI / HTTP Host，无需拷贝整个首包。
    [[nodiscard]] size_t CopyPrefixTo(uint8_t* out, size_t out_size) const {
        if (!out || out_size == 0) {
            return 0;
        }
        const size_t want = std::min(out_size, size());
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
            inline_size_ = 0;
            return std::move(overflow_);
        }
        buf::MultiBuffer mb;
        if (!buf::AppendSpanToMultiBuffer(span(), mb)) throw std::bad_alloc();
        inline_size_ = 0;
        return mb;
    }

    void assign(std::span<const uint8_t> data) {
        InitialPayload replacement;
        replacement.append(data);
        *this = std::move(replacement);
    }

    void append(std::span<const uint8_t> data) {
        if (data.empty()) return;
        if (data.size() > std::numeric_limits<size_t>::max() - size())
            throw std::length_error("InitialPayload size overflow");
        if (overflow_.empty() && data.size() <= inline_.size() - inline_size_) {
            std::memmove(inline_.data() + inline_size_, data.data(), data.size());
            inline_size_ += data.size();
            return;
        }
        if (!overflow_.empty()) {
            if (!buf::AppendSpanToMultiBuffer(data, overflow_)) throw std::bad_alloc();
            return;
        }

        buf::MultiBuffer replacement;
        if (!buf::AppendSpanToMultiBuffer(span(), replacement) ||
            !buf::AppendSpanToMultiBuffer(data, replacement)) throw std::bad_alloc();
        overflow_ = std::move(replacement);
        inline_size_ = 0;
    }

private:
    std::array<uint8_t, kInlineSize> inline_{};
    buf::MultiBuffer overflow_;
    size_t inline_size_ = 0;
};

}  // namespace acpp
