#pragma once

#include "acppnode/infra/json.hpp"

#include <expected>
#include <initializer_list>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace acpp {

[[nodiscard]] std::expected<std::optional<std::string>, std::string>
ParseAliasedJsonString(
    const json::object& source,
    std::initializer_list<std::string_view> aliases);

[[nodiscard]]
std::expected<std::optional<std::vector<std::string>>, std::string>
ParseAliasedJsonStringArray(
    const json::object& source,
    std::initializer_list<std::string_view> aliases);

}  // namespace acpp
