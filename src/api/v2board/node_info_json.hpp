#pragma once

#include "api/api.hpp"
#include "infra/json.hpp"

#include <tl/expected.hpp>
#include <string>
#include <string_view>

namespace api::v2board {

[[nodiscard]] tl::expected<::api::NodeInfo, std::string> ParseNodeInfo(
    const json::object& source,
    std::string_view node_type);

}  // namespace api::v2board
