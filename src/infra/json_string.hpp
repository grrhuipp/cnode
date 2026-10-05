#pragma once

#include "acppnode/infra/json.hpp"

#include <tl/expected.hpp>
#include <initializer_list>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace acpp {

[[nodiscard]] tl::expected<std::optional<std::string>, std::string>
ParseAliasedJsonString(
    const json::object& source,
    std::initializer_list<std::string_view> aliases);

[[nodiscard]]
tl::expected<std::optional<std::vector<std::string>>, std::string>
ParseAliasedJsonStringArray(
    const json::object& source,
    std::initializer_list<std::string_view> aliases);

}  // namespace acpp
