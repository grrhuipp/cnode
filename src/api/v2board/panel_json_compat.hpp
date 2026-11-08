#pragma once

#include "transport/internet/http_headers.hpp"
#include "infra/json_field.hpp"

#include <charconv>
#include <cstdint>
#include <optional>
#include <string_view>

namespace api::v2board {

// PHP encodes an empty associative-array configuration as [] instead of {}.
[[nodiscard]] inline bool IsPanelEmptyObject(const json::value& value) noexcept {
    return value.is_array() && value.as_array().empty();
}

[[nodiscard]] inline std::optional<uint64_t> PanelUnsignedInteger(
    const json::value& value) noexcept {
    if (const auto parsed = JsonUnsignedInteger(value)) {
        return parsed;
    }
    if (!value.is_string()) {
        return std::nullopt;
    }

    const std::string_view text = value.as_string();
    uint64_t parsed = 0;
    const auto [end, error] = std::from_chars(
        text.data(), text.data() + text.size(), parsed);
    if (text.empty() || error != std::errc{} ||
        end != text.data() + text.size()) {
        return std::nullopt;
    }
    return parsed;
}

[[nodiscard]] inline std::optional<bool> PanelBoolean(
    const json::value& value) noexcept {
    if (value.is_bool()) {
        return value.as_bool();
    }
    if (const auto number = PanelUnsignedInteger(value); number && *number <= 1) {
        return *number == 1;
    }
    if (value.is_string()) {
        const std::string_view text = value.as_string();
        if (transport::internet::EqualsAsciiCI(text, "true")) {
            return true;
        }
        if (transport::internet::EqualsAsciiCI(text, "false")) {
            return false;
        }
    }
    return std::nullopt;
}

}  // namespace api::v2board
