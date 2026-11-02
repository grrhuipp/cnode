#pragma once

#include "acppnode/infra/json.hpp"

#include <tl/expected.hpp>
#include <optional>
#include <string>
#include <string_view>

namespace acpp {

[[nodiscard]] tl::expected<std::optional<bool>, std::string>
ParseJsonBool(
    const json::object& source,
    std::string_view key);
}  // namespace acpp
