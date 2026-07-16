#include "acppnode/infra/json_object.hpp"

#include <format>

namespace acpp {

namespace {

bool JsonValuesEqual(const json::value& lhs, const json::value& rhs) {
    if (lhs.is_null()) return rhs.is_null();
    if (lhs.is_bool()) return rhs.is_bool() && lhs.as_bool() == rhs.as_bool();
    if (lhs.is_string()) {
        return rhs.is_string() && lhs.as_string() == rhs.as_string();
    }
    if (lhs.is_int64()) {
        return rhs.is_int64() && lhs.as_int64() == rhs.as_int64();
    }
    if (lhs.is_uint64()) {
        return rhs.is_uint64() && lhs.as_uint64() == rhs.as_uint64();
    }
    if (lhs.is_double()) {
        return rhs.is_double() && lhs.as_double() == rhs.as_double();
    }
    if (lhs.is_array()) {
        if (!rhs.is_array() || lhs.as_array().size() != rhs.as_array().size()) {
            return false;
        }
        auto lhs_it = lhs.as_array().begin();
        auto rhs_it = rhs.as_array().begin();
        for (; lhs_it != lhs.as_array().end(); ++lhs_it, ++rhs_it) {
            if (!JsonValuesEqual(*lhs_it, *rhs_it)) return false;
        }
        return true;
    }
    if (!rhs.is_object() || lhs.as_object().size() != rhs.as_object().size()) {
        return false;
    }
    auto lhs_it = lhs.as_object().begin();
    auto rhs_it = rhs.as_object().begin();
    for (; lhs_it != lhs.as_object().end(); ++lhs_it, ++rhs_it) {
        if (lhs_it->first != rhs_it->first ||
            !JsonValuesEqual(lhs_it->second, rhs_it->second)) {
            return false;
        }
    }
    return true;
}

}  // namespace

std::expected<const json::object*, std::string>
ParseAliasedJsonObject(
    const json::object& source,
    std::initializer_list<std::string_view> aliases) {
    const json::value* result = nullptr;
    std::string_view first_key;
    for (const std::string_view key : aliases) {
        const auto* raw = source.if_contains(key);
        if (!raw) continue;
        if (!raw->is_object()) {
            return std::unexpected(std::format("{} must be an object", key));
        }
        if (result && !JsonValuesEqual(*result, *raw)) {
            return std::unexpected(std::format(
                "{} and {} must match", first_key, key));
        }
        if (!result) {
            result = raw;
            first_key = key;
        }
    }
    return result ? &result->as_object() : nullptr;
}

}  // namespace acpp
