#include "http2_initial_window.hpp"

#include "infra/json_field.hpp"

#include <utility>


tl::expected<std::optional<uint32_t>, std::string>
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

