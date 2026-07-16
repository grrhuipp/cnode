#pragma once

#include "acppnode/infra/json.hpp"

#include <expected>
#include <initializer_list>
#include <string>
#include <string_view>

namespace acpp {

// The returned object aliases source and is valid only while source remains
// alive and unmodified.
[[nodiscard]] std::expected<const json::object*, std::string>
ParseAliasedJsonObject(
    const json::object& source,
    std::initializer_list<std::string_view> aliases);

}  // namespace acpp
