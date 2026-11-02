#pragma once

#include "acppnode/app/proxyman/outbound/prepared_config.hpp"
#include "acppnode/infra/panel_config.hpp"

#include <string>

namespace acpp::controller {

[[nodiscard]] proxyman::outbound::PreparedOutboundConfig OutboundBuilder(
    const std::string& tag,
    const PanelConfig& panel_config);

}  // namespace acpp::controller
