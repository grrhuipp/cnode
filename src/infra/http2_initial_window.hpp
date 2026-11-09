#pragma once

#include "infra/json.hpp"
#include "infra/json_field.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <tl/expected.hpp>
#include <utility>


inline constexpr uint32_t kHttp2MaxInitialWindow = 0x7fffffffU;

[[nodiscard]] inline tl::expected<std::optional<uint32_t>, std::string>
ParseHttp2InitialWindow(const json::object& source) {
    if (source.contains("initial_windows_size") ||
        source.contains("initial_window_size")) {
        return tl::unexpected(std::string(
            "initial_windows_size/initial_window_size is not supported; use initialWindowSize"));
    }
    auto parsed = ParseJsonUint64(
        source,
        "initialWindowSize",
        kHttp2MaxInitialWindow);
    if (!parsed) {
        return tl::unexpected(std::move(parsed.error()));
    }
    if (!*parsed) {
        return std::optional<uint32_t>{};
    }
    return std::optional<uint32_t>{static_cast<uint32_t>(**parsed)};
}

