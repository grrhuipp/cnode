#pragma once

#include "acppnode/api/api.hpp"
#include "acppnode/common/online_device.hpp"

#include <cstddef>
#include <vector>

namespace acpp::controller {

struct OnlineSnapshot {
    std::vector<api::OnlineUser> entries;
    size_t user_count = 0;
};

[[nodiscard]] OnlineSnapshot
BuildOnlineSnapshot(std::vector<OnlineDevice> devices);

}  // namespace acpp::controller
