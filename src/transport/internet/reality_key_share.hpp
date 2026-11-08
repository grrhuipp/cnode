#pragma once

#include "transport/internet/reality_key.hpp"

#include <cstdint>
#include <tl/expected.hpp>
#include <span>

namespace transport::internet {

enum class RealityKeyShareError {
    InvalidFormat,
};

[[nodiscard]] tl::expected<RealityKey, RealityKeyShareError>
ParseRealityClientKeyShareExtension(
    std::span<const uint8_t> extension) noexcept;

}  // namespace transport::internet
