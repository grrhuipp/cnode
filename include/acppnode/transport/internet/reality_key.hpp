#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <string_view>

namespace acpp::transport::internet {

inline constexpr std::size_t kRealityKeySize = 32;
using RealityKey = std::array<uint8_t, kRealityKeySize>;

enum class RealityKeyError {
    InvalidFormat,
};

[[nodiscard]] std::expected<RealityKey, RealityKeyError>
ParseRealityKey(std::string_view value) noexcept;

}  // namespace acpp::transport::internet
