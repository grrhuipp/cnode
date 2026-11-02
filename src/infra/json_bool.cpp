#include "json_bool.hpp"

#include <format>

namespace acpp {

std::expected<std::optional<bool>, std::string>
ParseJsonBool(
    const json::object& source,
    std::string_view key) {
    const auto* raw = source.if_contains(key);
    if (!raw) {
        return std::optional<bool>{};
    }
    if (!raw->is_bool()) {
        return std::unexpected(
            std::format("{} must be a boolean", key));
    }
    return std::optional<bool>{raw->as_bool()};
}
}  // namespace acpp
