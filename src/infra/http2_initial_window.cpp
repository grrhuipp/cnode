#include "http2_initial_window.hpp"

#include <format>
#include <string_view>

namespace acpp {

std::expected<std::optional<uint32_t>, std::string>
ParseHttp2InitialWindow(const json::object& source) {
    std::optional<uint32_t> result;
    std::string_view first_key;
    for (const std::string_view key : {"initialWindowSize", "initial_window_size"}) {
        const auto* raw = source.if_contains(key);
        if (!raw) continue;

        uint64_t value = 0;
        if (raw->is_int64()) {
            const int64_t signed_value = raw->as_int64();
            if (signed_value < 0) {
                return std::unexpected(std::format(
                    "{} must be between 0 and {}", key, kHttp2MaxInitialWindow));
            }
            value = static_cast<uint64_t>(signed_value);
        } else if (raw->is_uint64()) {
            value = raw->as_uint64();
        } else {
            return std::unexpected(std::format("{} must be an integer", key));
        }

        if (value > kHttp2MaxInitialWindow) {
            return std::unexpected(std::format(
                "{} must be between 0 and {}", key, kHttp2MaxInitialWindow));
        }
        const uint32_t parsed = static_cast<uint32_t>(value);
        if (result && *result != parsed) {
            return std::unexpected(std::format(
                "{} and {} must match", first_key, key));
        }
        if (!result) {
            result = parsed;
            first_key = key;
        }
    }
    return result;
}

}  // namespace acpp
