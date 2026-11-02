#pragma once

#include "acppnode/infra/json.hpp"

#include <tl/expected.hpp>
#include <string>
#include <string_view>

namespace acpp {

// The returned object borrows from source and is valid only while source
// remains alive and unmodified.
[[nodiscard]] tl::expected<const json::object*, std::string>
ParseJsonObject(
    const json::object& source,
    std::string_view key);
}  // namespace acpp
