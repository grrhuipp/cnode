#pragma once

#include "acppnode/api/api.hpp"
#include "acppnode/service/controller/config.hpp"

namespace acpp::controller {

[[nodiscard]] inline bool ShouldEnableInboundTls(
    const PanelConfig* panel_config,
    const api::NodeInfo& node_config) noexcept {
    return node_config.EnableTLS
        && (panel_config == nullptr || panel_config->TLSEnable);
}

}  // namespace acpp::controller
