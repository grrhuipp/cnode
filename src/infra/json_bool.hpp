#pragma once

#include "acppnode/infra/json.hpp"

#include <tl/expected.hpp>
#include <initializer_list>
#include <optional>
#include <string>
#include <string_view>

namespace acpp {

[[nodiscard]] tl::expected<std::optional<bool>, std::string>
ParseAliasedJsonBool(
    const json::object& source,
    std::initializer_list<std::string_view> aliases);

}  // namespace acpp
