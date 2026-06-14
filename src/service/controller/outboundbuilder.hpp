#pragma once

#include "acppnode/api/api.hpp"
#include "acppnode/app/proxyman/outbound/prepared_config.hpp"
#include "acppnode/service/controller/config.hpp"

#include <string>

namespace acpp::controller {

[[nodiscard]] proxyman::outbound::PreparedOutboundConfig OutboundBuilder(
    const std::string& tag,
    const PanelConfig* panel_config,
    const api::NodeInfo& node_config);

}  // namespace acpp::controller
