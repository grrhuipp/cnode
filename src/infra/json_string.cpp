#include "json_string.hpp"

#include <format>
#include <utility>

namespace acpp {

std::expected<std::optional<std::string>, std::string>
ParseAliasedJsonString(
    const json::object& source,
    std::initializer_list<std::string_view> aliases) {
    std::optional<std::string> result;
    std::string_view first_key;
    for (const std::string_view key : aliases) {
        const auto* raw = source.if_contains(key);
        if (!raw) continue;
        if (!raw->is_string()) {
            return std::unexpected(
                std::format("{} must be a string", key));
        }

        std::string value(raw->as_string());
        if (result && *result != value) {
            return std::unexpected(std::format(
                "{} and {} must match", first_key, key));
        }
        if (!result) {
            result = std::move(value);
            first_key = key;
        }
    }
    return result;
}

std::expected<std::optional<std::vector<std::string>>, std::string>
ParseAliasedJsonStringArray(
    const json::object& source,
    std::initializer_list<std::string_view> aliases) {
    std::optional<std::vector<std::string>> result;
    std::string_view first_key;
    for (const std::string_view key : aliases) {
        const auto* raw = source.if_contains(key);
        if (!raw) continue;
        if (!raw->is_array()) {
            return std::unexpected(std::format(
                "{} must be an array of strings", key));
        }

        std::vector<std::string> values;
        values.reserve(raw->as_array().size());
        for (const auto& item : raw->as_array()) {
            if (!item.is_string()) {
                return std::unexpected(std::format(
                    "{} must contain only strings", key));
            }
            values.emplace_back(item.as_string());
        }
        if (result && *result != values) {
            return std::unexpected(std::format(
                "{} and {} must match", first_key, key));
        }
        if (!result) {
            result = std::move(values);
            first_key = key;
        }
    }
    return result;
}

}  // namespace acpp
