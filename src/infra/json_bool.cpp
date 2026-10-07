#include "json_bool.hpp"

#include <format>

namespace acpp {

std::expected<std::optional<bool>, std::string>
ParseAliasedJsonBool(
    const json::object& source,
    std::initializer_list<std::string_view> aliases) {
    std::optional<bool> result;
    std::string_view first_key;
    for (const std::string_view key : aliases) {
        const auto* raw = source.if_contains(key);
        if (!raw) continue;
        if (!raw->is_bool()) {
            return std::unexpected(
                std::format("{} must be a boolean", key));
        }

        const bool value = raw->as_bool();
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
