#pragma once

#include "acppnode/common.hpp"

namespace acpp {
class PanelSyncManager;
}

namespace acpp {

void SetupPanels(net::io_context& main_ctx,
                 PanelSyncManager& sync_manager,
                 const Config& config);

}  // namespace acpp
