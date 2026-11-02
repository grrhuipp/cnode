#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <string_view>

namespace acpp::transport::internet {

inline constexpr std::size_t kRealityShortIdSize = 8;
using RealityShortId = std::array<uint8_t, kRealityShortIdSize>;

enum class RealityShortIdError {
    InvalidFormat,
};

[[nodiscard]] std::expected<RealityShortId, RealityShortIdError>
ParseRealityShortId(std::string_view value) noexcept;

}  // namespace acpp::transport::internet
