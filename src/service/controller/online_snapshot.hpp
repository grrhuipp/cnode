#pragma once

#include "api/api.hpp"
#include "common/online_device.hpp"

#include <cstddef>
#include <vector>

namespace controller {

struct OnlineSnapshot {
    std::vector<api::OnlineUser> entries;
    size_t user_count = 0;
};

[[nodiscard]] OnlineSnapshot
BuildOnlineSnapshot(std::vector<OnlineDevice> devices);

}  // namespace controller
