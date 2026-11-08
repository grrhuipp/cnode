#pragma once

#include "api/api.hpp"
#include "core/constants.hpp"
#include "infra/panel_config.hpp"

namespace controller {

[[nodiscard]] inline bool ShouldEnableInboundTls(
    const PanelConfig& panel_config,
    const api::NodeInfo& node_config) noexcept {
    if (!panel_config.TLSEnable) {
        return false;
    }

    // These protocols always terminate TLS; the panel switch declares that
    // this cnode instance owns a usable certificate.
    return node_config.EnableTLS ||
        node_config.NodeType == constants::protocol::kAnyTLS ||
        node_config.NodeType == constants::protocol::kTrojan ||
        node_config.NodeType == constants::protocol::kHysteria ||
        node_config.NodeType == constants::protocol::kHysteria2;
}

}  // namespace controller
