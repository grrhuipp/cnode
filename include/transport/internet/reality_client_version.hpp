#pragma once

#include <array>
#include <cstdint>
#include <tl/expected.hpp>
#include <optional>
#include <span>
#include <string_view>

namespace transport::internet {

using RealityClientVersion = std::array<uint8_t, 4>;

enum class RealityClientVersionError {
    InvalidFormat,
};

[[nodiscard]] tl::expected<
    std::optional<RealityClientVersion>, RealityClientVersionError>
ParseRealityClientVersion(std::string_view value) noexcept;

[[nodiscard]] uint32_t RealityClientVersionValue(
    std::span<const uint8_t, 4> version) noexcept;

}  // namespace transport::internet
