#pragma once

#include <array>
#include <cstdint>

namespace transport::internet {

[[nodiscard]] constexpr std::array<uint8_t, 6> EncodeInitialWindowSetting(
    uint32_t value) noexcept {
    return {{
        0,
        4,  // SETTINGS_INITIAL_WINDOW_SIZE
        static_cast<uint8_t>(value >> 24),
        static_cast<uint8_t>(value >> 16),
        static_cast<uint8_t>(value >> 8),
        static_cast<uint8_t>(value),
    }};
}

}  // namespace transport::internet
