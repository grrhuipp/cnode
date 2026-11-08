#pragma once

#include "common/binary_text_codec.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>

namespace proxy {

// Parses exactly 32 hexadecimal digits; '-' separators are ignored wherever
// they appear. Signs, whitespace and prefixes are rejected.
[[nodiscard]] inline std::optional<std::array<uint8_t, 16>>
ParseUuid(std::string_view text) noexcept {
    std::array<uint8_t, 16> out{};
    size_t nibble_index = 0;
    for (const char ch : text) {
        if (ch == '-') {
            continue;
        }
        const int value = HexDigitValue(ch);
        if (value < 0 || nibble_index >= 32) {
            return std::nullopt;
        }
        uint8_t& byte = out[nibble_index / 2];
        byte = (nibble_index & 1) == 0
            ? static_cast<uint8_t>(value << 4)
            : static_cast<uint8_t>(byte | value);
        ++nibble_index;
    }
    if (nibble_index != 32) {
        return std::nullopt;
    }
    return out;
}

}  // namespace proxy
