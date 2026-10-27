#pragma once

#include "acppnode/infra/json.hpp"

#include <expected>
#include <optional>
#include <string>
#include <string_view>

namespace acpp {

[[nodiscard]] std::expected<std::optional<bool>, std::string>
ParseJsonBool(
    const json::object& source,
    std::string_view key);
}  // namespace acpp
