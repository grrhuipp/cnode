#include "acppnode/infra/json_object.hpp"

#include <format>

namespace acpp {

std::expected<const json::object*, std::string>
ParseJsonObject(
    const json::object& source,
    std::string_view key) {
    const auto* raw = source.if_contains(key);
    if (!raw) {
        return nullptr;
    }
    if (!raw->is_object()) {
        return std::unexpected(std::format("{} must be an object", key));
    }
    return &raw->as_object();
}

}  // namespace acpp
