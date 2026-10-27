#include "json_unsigned.hpp"

#include <format>

namespace acpp {

std::expected<std::optional<uint64_t>, std::string>
ParseJsonUint64(
    const json::object& source,
    std::string_view key,
    uint64_t maximum) {
    const auto* raw = source.if_contains(key);
    if (!raw) {
        return std::optional<uint64_t>{};
    }

    uint64_t value = 0;
    if (raw->is_int64()) {
        const int64_t signed_value = raw->as_int64();
        if (signed_value < 0) {
            return std::unexpected(std::format(
                "{} must be an integer between 0 and {}", key, maximum));
        }
        value = static_cast<uint64_t>(signed_value);
    } else if (raw->is_uint64()) {
        value = raw->as_uint64();
    } else {
        return std::unexpected(std::format(
            "{} must be an integer between 0 and {}", key, maximum));
    }

    if (value > maximum) {
        return std::unexpected(std::format(
            "{} must be an integer between 0 and {}", key, maximum));
    }
    return std::optional<uint64_t>{value};
}
}  // namespace acpp
