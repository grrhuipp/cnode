#pragma once

#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <string_view>

namespace acpp::transport::internet {

enum class RealityServerNameExtensionError {
    InvalidFormat,
};

[[nodiscard]] std::expected<std::string_view, RealityServerNameExtensionError>
ParseRealityServerNameExtension(std::span<const uint8_t> extension) noexcept;

[[nodiscard]] bool IsRealityServerNameAllowed(
    std::span<const std::string> allowed,
    std::string_view requested) noexcept;

}  // namespace acpp::transport::internet
