#pragma once

#include "acppnode/api/api.hpp"
#include "acppnode/core/constants.hpp"
#include "acppnode/service/controller/config.hpp"

namespace acpp::controller {

[[nodiscard]] inline bool ShouldEnableInboundTls(
    const PanelConfig* panel_config,
    const api::NodeInfo& node_config) noexcept {
    if (panel_config && !panel_config->TLSEnable) {
        return false;
    }

    // V2Board AnyTLS and Trojan nodes do not expose the generic `tls` field;
    // both subscription protocols always connect through TLS. The local panel
    // switch is authoritative for whether this process may terminate TLS.
    return node_config.EnableTLS ||
        node_config.NodeType == constants::protocol::kAnyTLS ||
        node_config.NodeType == constants::protocol::kTrojan;
}

}  // namespace acpp::controller
