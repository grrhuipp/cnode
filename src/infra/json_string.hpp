#pragma once

#include "acppnode/infra/json.hpp"

#include <expected>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace acpp {

[[nodiscard]] std::expected<std::optional<std::string>, std::string>
ParseJsonString(
    const json::object& source,
    std::string_view key);

[[nodiscard]]
std::expected<std::optional<std::vector<std::string>>, std::string>
ParseJsonStringArray(
    const json::object& source,
    std::string_view key);
}  // namespace acpp
