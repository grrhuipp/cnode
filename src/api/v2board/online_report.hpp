#pragma once

#include "acppnode/api/api.hpp"
#include "acppnode/infra/json.hpp"

#include <cstddef>
#include <span>

namespace acpp::api::v2board {

struct OnlineReportPayload {
    json::object alive_body;
    size_t user_count = 0;
    size_t device_count = 0;
};

[[nodiscard]] OnlineReportPayload BuildOnlineReportPayload(
    std::span<const ::acpp::api::OnlineUser> online_devices,
    int node_id);

}  // namespace acpp::api::v2board
