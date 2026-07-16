#pragma once

#include <array>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string_view>

namespace acpp::transport::internet {

using RealityClientVersion = std::array<uint8_t, 4>;

enum class RealityClientVersionError {
    InvalidFormat,
};

[[nodiscard]] std::expected<
    std::optional<RealityClientVersion>, RealityClientVersionError>
ParseRealityClientVersion(std::string_view value) noexcept;

[[nodiscard]] uint32_t RealityClientVersionValue(
    std::span<const uint8_t, 4> version) noexcept;

}  // namespace acpp::transport::internet
