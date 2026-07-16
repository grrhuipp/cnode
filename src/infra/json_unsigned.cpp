#include "json_unsigned.hpp"

#include <format>

namespace acpp {

std::expected<std::optional<uint64_t>, std::string>
ParseAliasedJsonUint64(
    const json::object& source,
    std::initializer_list<std::string_view> aliases,
    uint64_t maximum) {
    std::optional<uint64_t> result;
    std::string_view first_key;
    for (const std::string_view key : aliases) {
        const auto* raw = source.if_contains(key);
        if (!raw) continue;

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
        if (result && *result != value) {
            return std::unexpected(std::format(
                "{} and {} must match", first_key, key));
        }
        if (!result) {
            result = value;
            first_key = key;
        }
    }
    return result;
}

}  // namespace acpp
