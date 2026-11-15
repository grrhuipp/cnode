#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <string_view>
#include <vector>

namespace transport {

// Append-only serialization buffer for one HTTP/1 header section or HPACK
// header block: typical blocks stay in the inline array, larger ones move to
// the heap once and grow there.
class HeaderBlockBuffer final {
public:
    static constexpr size_t kInlineCapacity = 512;

    void reserve(size_t total) {
        if (spilled_) {
            heap_.reserve(total);
        } else if (total > kInlineCapacity) {
            Spill(total);
        }
    }

    void push_back(uint8_t byte) {
        if (!spilled_ && inline_size_ < kInlineCapacity) {
            inline_[inline_size_++] = byte;
            return;
        }
        if (!spilled_) {
            Spill(inline_size_ + 1);
        }
        heap_.push_back(byte);
    }

    void append(std::string_view text) {
        if (text.empty()) {
            return;
        }
        if (!spilled_ && text.size() <= kInlineCapacity - inline_size_) {
            std::memcpy(inline_.data() + inline_size_, text.data(), text.size());
            inline_size_ += text.size();
            return;
        }
        if (!spilled_) {
            Spill(inline_size_ + text.size());
        }
        const auto* bytes = reinterpret_cast<const uint8_t*>(text.data());
        heap_.insert(heap_.end(), bytes, bytes + text.size());
    }

    [[nodiscard]] std::span<const uint8_t> Span() const noexcept {
        return spilled_ ? std::span<const uint8_t>(heap_)
                        : std::span<const uint8_t>(inline_.data(), inline_size_);
    }

    [[nodiscard]] std::string_view View() const noexcept {
        const auto bytes = Span();
        return {reinterpret_cast<const char*>(bytes.data()), bytes.size()};
    }

private:
    void Spill(size_t needed) {
        heap_.reserve(std::max(needed, kInlineCapacity * 2));
        heap_.assign(inline_.data(), inline_.data() + inline_size_);
        spilled_ = true;
    }

    std::array<uint8_t, kInlineCapacity> inline_{};
    std::vector<uint8_t> heap_;
    size_t inline_size_ = 0;
    bool spilled_ = false;
};

}  // namespace transport
