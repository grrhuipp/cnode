#include "acppnode/app/bootstrap_panels.hpp"

#include "acppnode/app/panel_sync.hpp"
#include "acppnode/infra/config.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/panel/v2board_panel.hpp"

namespace acpp {

void SetupPanels(net::io_context& main_ctx,
                 PanelSyncManager& sync_manager,
                 const Config& config) {
    if (config.GetPanels().empty()) {
        return;
    }

    LOG_CONSOLE("Panels:");
    for (const auto& panel_config : config.GetPanels()) {
        V2BoardConfig v2cfg;
        v2cfg.name      = panel_config.name;
        v2cfg.api_host  = panel_config.api_host;
        v2cfg.api_key   = panel_config.api_key;
        v2cfg.node_type = panel_config.node_type;

        // 面板同步临时改走 Asio resolver，避开当前自定义 DNS 协程崩溃路径。
        auto panel = CreateV2BoardPanel(main_ctx.get_executor(), v2cfg, nullptr);
        sync_manager.AddPanel(std::move(panel), panel_config);

        std::string node_ids_str;
        for (size_t i = 0; i < panel_config.node_ids.size(); ++i) {
            if (i > 0) node_ids_str += ", ";
            node_ids_str += std::to_string(panel_config.node_ids[i]);
        }
        LOG_CONSOLE("  - {} [{}] ({}): nodes=[{}]",
                    panel_config.name, panel_config.node_type,
                    panel_config.api_host, node_ids_str);
    }
}

}  // namespace acpp
