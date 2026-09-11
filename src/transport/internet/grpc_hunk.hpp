#pragma once

#include "acppnode/common/allocator.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string_view>

namespace acpp::transport::internet {

inline constexpr size_t kMaxGrpcHunkMessageSize = 4 * 1024 * 1024;

// Worker-local framing state. Only received bytes grow storage. A complete
// protobuf message is validated before exposing its final singular data field.
class GrpcHunkDecoder final {
public:
    GrpcHunkDecoder() = default;
    GrpcHunkDecoder(const GrpcHunkDecoder&) = delete;
    GrpcHunkDecoder& operator=(const GrpcHunkDecoder&) = delete;

    [[nodiscard]] std::expected<size_t, std::string_view> Feed(std::span<const uint8_t> bytes);
    [[nodiscard]] std::span<const uint8_t> Payload() const noexcept;
    void Consume(size_t size) noexcept;
    void Clear() noexcept;
    [[nodiscard]] bool AtMessageBoundary() const noexcept { return prefix_size_ == 0; }

private:
    std::array<uint8_t, 5> prefix_{};
    size_t prefix_size_ = 0;
    size_t message_size_ = 0;
    memory::ByteVector message_;
    size_t data_offset_ = 0;
    size_t data_end_ = 0;
};

}  // namespace acpp::transport::internet
