#pragma once

#include "acppnode/api/api.hpp"
#include "acppnode/app/proxyman/outbound/prepared_config.hpp"
#include "acppnode/service/controller/config.hpp"

#include <optional>
#include <string>

namespace acpp::controller {

[[nodiscard]] std::optional<proxyman::outbound::PreparedOutboundConfig> OutboundBuilder(
    const std::string& tag,
    const PanelConfig* panel_config,
    const api::NodeInfo& node_config);

}  // namespace acpp::controller
