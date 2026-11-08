#pragma once

#include "api/api.hpp"
#include "infra/json.hpp"

#include <tl/expected.hpp>
#include <string>
#include <vector>

namespace api::v2board {

[[nodiscard]] tl::expected<std::vector<::api::UserInfo>, std::string>
ParseUserList(const json::object& source);

}  // namespace api::v2board
