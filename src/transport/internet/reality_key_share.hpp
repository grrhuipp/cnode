#pragma once

#include "acppnode/transport/internet/reality_key.hpp"

#include <cstdint>
#include <expected>
#include <span>

namespace acpp::transport::internet {

enum class RealityKeyShareError {
    InvalidFormat,
};

[[nodiscard]] std::expected<RealityKey, RealityKeyShareError>
ParseRealityClientKeyShareExtension(
    std::span<const uint8_t> extension) noexcept;

}  // namespace acpp::transport::internet
