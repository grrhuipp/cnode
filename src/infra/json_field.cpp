#include "infra/json_field.hpp"

#include <format>
#include <stdexcept>
#include <utility>


std::optional<uint64_t> JsonUnsignedInteger(const json::value& value) noexcept {
    if (value.is_uint64()) {
        return value.as_uint64();
    }
    if (value.is_int64() && value.as_int64() >= 0) {
        return static_cast<uint64_t>(value.as_int64());
    }
    return std::nullopt;
}

tl::expected<std::optional<bool>, std::string>
ParseJsonBool(const json::object& source, std::string_view key) {
    const auto* raw = source.if_contains(key);
    if (!raw) {
        return std::optional<bool>{};
    }
    if (!raw->is_bool()) {
        return tl::unexpected(std::format("{} must be a boolean", key));
    }
    return std::optional<bool>{raw->as_bool()};
}

tl::expected<std::optional<std::string>, std::string>
ParseJsonString(const json::object& source, std::string_view key) {
    const auto* raw = source.if_contains(key);
    if (!raw) {
        return std::optional<std::string>{};
    }
    if (!raw->is_string()) {
        return tl::unexpected(std::format("{} must be a string", key));
    }
    return std::optional<std::string>{std::string(raw->as_string())};
}

tl::expected<std::optional<std::vector<std::string>>, std::string>
ParseJsonStringArray(const json::object& source, std::string_view key) {
    const auto* raw = source.if_contains(key);
    if (!raw) {
        return std::optional<std::vector<std::string>>{};
    }
    if (!raw->is_array()) {
        return tl::unexpected(std::format(
            "{} must be an array of strings", key));
    }

    std::vector<std::string> values;
    values.reserve(raw->as_array().size());
    for (const auto& item : raw->as_array()) {
        if (!item.is_string()) {
            return tl::unexpected(std::format(
                "{} must contain only strings", key));
        }
        values.emplace_back(item.as_string());
    }
    return std::optional<std::vector<std::string>>{std::move(values)};
}

tl::expected<std::optional<uint64_t>, std::string>
ParseJsonUint64(
    const json::object& source,
    std::string_view key,
    uint64_t maximum) {
    const auto* raw = source.if_contains(key);
    if (!raw) {
        return std::optional<uint64_t>{};
    }
    const auto value = JsonUnsignedInteger(*raw);
    if (!value || *value > maximum) {
        return tl::unexpected(std::format(
            "{} must be an integer between 0 and {}", key, maximum));
    }
    return std::optional<uint64_t>{*value};
}

tl::expected<const json::object*, std::string>
ParseJsonObject(const json::object& source, std::string_view key) {
    const auto* raw = source.if_contains(key);
    if (!raw) {
        return nullptr;
    }
    if (!raw->is_object()) {
        return tl::unexpected(std::format("{} must be an object", key));
    }
    return &raw->as_object();
}

std::string JsonStringOr(
    const json::object& source, std::string_view key, std::string_view fallback) {
    auto parsed = ParseJsonString(source, key);
    if (!parsed) {
        throw std::invalid_argument(std::move(parsed.error()));
    }
    if (!*parsed) {
        return std::string(fallback);
    }
    return std::move(**parsed);
}

bool JsonBoolOr(const json::object& source, std::string_view key, bool fallback) {
    auto parsed = ParseJsonBool(source, key);
    if (!parsed) {
        throw std::invalid_argument(std::move(parsed.error()));
    }
    return parsed->value_or(fallback);
}

JsonPortResult ReadJsonPort(
    const json::object& source, std::string_view key) noexcept {
    const auto* raw = source.if_contains(key);
    if (!raw) {
        return {};
    }
    if (!raw->is_int64() && !raw->is_uint64()) {
        return {.error = JsonPortError::InvalidType};
    }
    const auto value = JsonUnsignedInteger(*raw);
    if (!value || *value == 0 || *value > std::numeric_limits<uint16_t>::max()) {
        return {.error = JsonPortError::OutOfRange};
    }
    return {
        .error = JsonPortError::None,
        .value = static_cast<uint16_t>(*value),
    };
}

