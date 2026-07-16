#pragma once

#include "acppnode/common/allocator.hpp"
#include "acppnode/common/asio_types.hpp"
#include "acppnode/common/buf/multi_buffer.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>

namespace acpp::detail {

class UdpReceiveBuffer final {
public:
    static constexpr size_t kMaxWireBytes = 65535;

    [[nodiscard]] net::mutable_buffer Prepare(size_t available_bytes) {
        large_.clear();
        small_ = buf::BufferGuard{};

        const size_t capacity = std::clamp<size_t>(
            available_bytes, 1, kMaxWireBytes);
        if (capacity <= buf::Buffer::kSize) {
            small_ = buf::BufferGuard{buf::Buffer::New()};
            if (!small_) {
                return {};
            }
            return net::buffer(small_->data, buf::Buffer::kSize);
        }

        large_.resize(capacity);
        return net::buffer(large_.data(), large_.size());
    }

    [[nodiscard]] std::span<const uint8_t> Data(size_t bytes) const noexcept {
        if (!large_.empty()) {
            return std::span<const uint8_t>(
                large_.data(), std::min(bytes, large_.size()));
        }
        if (small_) {
            return std::span<const uint8_t>(
                small_->data,
                std::min(bytes, static_cast<size_t>(buf::Buffer::kSize)));
        }
        return {};
    }

private:
    buf::BufferGuard small_;
    memory::ByteVector large_;
};

}  // namespace acpp::detail
