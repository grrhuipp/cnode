#pragma once

#include <chrono>
#include <cstdint>

namespace acpp::controller {

[[nodiscard]] constexpr std::chrono::seconds PanelInterval(
    int configured_seconds,
    uint32_t fallback_seconds) noexcept {
    return std::chrono::seconds(
        configured_seconds > 0
            ? static_cast<uint32_t>(configured_seconds)
            : fallback_seconds);
}

}  // namespace acpp::controller
