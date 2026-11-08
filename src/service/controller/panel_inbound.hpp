#pragma once

#include "api/api.hpp"
#include "infra/config_types.hpp"
#include "infra/panel_config.hpp"

#include <span>
#include <vector>

namespace controller {

// Panel configuration mapping: node and user records to the source-neutral
// InboundSpec consumed by the shared inbound builder. Throws
// std::invalid_argument when the node's stream settings are unsupported.
[[nodiscard]] InboundSpec MapPanelInbound(
    const PanelConfig& panel_config,
    const api::NodeInfo& node_config,
    std::span<const api::UserInfo> users);

[[nodiscard]] std::vector<InboundUserSpec> MapPanelUsers(
    const api::NodeInfo& node_config,
    std::span<const api::UserInfo> users);

}  // namespace controller
