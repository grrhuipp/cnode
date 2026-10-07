#pragma once

#include "acppnode/api/api.hpp"
#include "acppnode/infra/json.hpp"

#include <expected>
#include <string>
#include <string_view>

namespace acpp::api::v2board {

[[nodiscard]] std::expected<::acpp::api::NodeInfo, std::string> ParseNodeInfo(
    const json::object& source,
    int node_id,
    std::string_view node_type);

}  // namespace acpp::api::v2board
