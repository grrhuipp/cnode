#pragma once

#include "api/api.hpp"
#include "infra/json.hpp"

#include <cstddef>
#include <span>

namespace api::v2board {

struct OnlineReportPayload {
    json::object alive_body;
    size_t user_count = 0;
    size_t device_count = 0;
};

[[nodiscard]] OnlineReportPayload BuildOnlineReportPayload(
    std::span<const ::api::OnlineUser> online_devices,
    int node_id);

}  // namespace api::v2board
