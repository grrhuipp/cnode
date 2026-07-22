#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace acpp {

// Worker-local capture of the raw inbound wire prefix. It is attached only
// during transport/protocol admission and cleared once Dispatcher is reached.
class ReadPrefixCapture final {
public:
    static constexpr std::size_t kMaxBytes = 8U * 1024U;

    void Append(std::span<const std::uint8_t> bytes) {
        if (bytes.empty()) return;
        original_size_ += bytes.size();
        const auto available = kMaxBytes - bytes_.size();
        const auto count = std::min(available, bytes.size());
        bytes_.insert(bytes_.end(), bytes.begin(), bytes.begin() + count);
        truncated_ = truncated_ || count < bytes.size();
    }

    [[nodiscard]] const std::vector<std::uint8_t>& Bytes() const noexcept {
        return bytes_;
    }

    [[nodiscard]] bool Truncated() const noexcept { return truncated_; }
    [[nodiscard]] std::uint64_t OriginalSize() const noexcept {
        return original_size_;
    }

private:
    std::vector<std::uint8_t> bytes_;
    std::uint64_t original_size_ = 0;
    bool truncated_ = false;
};

}  // namespace acpp
