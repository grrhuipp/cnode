#pragma once

#include "acppnode/api/api.hpp"

namespace acpp::serverstatus {

[[nodiscard]] api::NodeStatus GetSystemInfo();

}  // namespace acpp::serverstatus
