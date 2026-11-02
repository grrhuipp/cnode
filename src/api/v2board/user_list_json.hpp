#pragma once

#include "acppnode/api/api.hpp"
#include "acppnode/infra/json.hpp"

#include <expected>
#include <string>
#include <vector>

namespace acpp::api::v2board {

[[nodiscard]] std::expected<std::vector<::acpp::api::UserInfo>, std::string>
ParseUserList(const json::object& source);

}  // namespace acpp::api::v2board
