#pragma once

#include "acppnode/infra/json.hpp"

#include <tl/expected.hpp>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace acpp {

[[nodiscard]] tl::expected<std::optional<std::string>, std::string>
ParseJsonString(
    const json::object& source,
    std::string_view key);

[[nodiscard]]
tl::expected<std::optional<std::vector<std::string>>, std::string>
ParseJsonStringArray(
    const json::object& source,
    std::string_view key);
}  // namespace acpp
