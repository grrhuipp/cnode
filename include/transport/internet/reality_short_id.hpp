#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <tl/expected.hpp>
#include <string_view>

namespace transport::internet {

inline constexpr std::size_t kRealityShortIdSize = 8;
using RealityShortId = std::array<uint8_t, kRealityShortIdSize>;

enum class RealityShortIdError {
    InvalidFormat,
};

[[nodiscard]] tl::expected<RealityShortId, RealityShortIdError>
ParseRealityShortId(std::string_view value) noexcept;

}  // namespace transport::internet
