#pragma once

#include "acppnode/api/api.hpp"
#include "acppnode/infra/json.hpp"

#include <tl/expected.hpp>
#include <string>
#include <vector>

namespace acpp::api::v2board {

[[nodiscard]] tl::expected<std::vector<::acpp::api::UserInfo>, std::string>
ParseUserList(const json::object& source);

}  // namespace acpp::api::v2board
