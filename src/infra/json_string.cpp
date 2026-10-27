#include "json_string.hpp"

#include <format>
#include <utility>

namespace acpp {

std::expected<std::optional<std::string>, std::string>
ParseJsonString(
    const json::object& source,
    std::string_view key) {
    const auto* raw = source.if_contains(key);
    if (!raw) {
        return std::optional<std::string>{};
    }
    if (!raw->is_string()) {
        return std::unexpected(
            std::format("{} must be a string", key));
    }
    return std::optional<std::string>{std::string(raw->as_string())};
}

std::expected<std::optional<std::vector<std::string>>, std::string>
ParseJsonStringArray(
    const json::object& source,
    std::string_view key) {
    const auto* raw = source.if_contains(key);
    if (!raw) {
        return std::optional<std::vector<std::string>>{};
    }
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
    return std::optional<std::vector<std::string>>{std::move(values)};
}
}  // namespace acpp
