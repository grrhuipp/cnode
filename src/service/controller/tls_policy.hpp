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

    // V2Board AnyTLS nodes may omit the generic `tls` flag even though the
    // subscription protocol always connects through TLS. The local panel
    // switch is authoritative for whether this process may terminate TLS.
    return node_config.EnableTLS ||
        node_config.NodeType == constants::protocol::kAnyTLS;
}

}  // namespace acpp::controller
