#include "app/bootstrap_panels.hpp"

#include "api/panel_factory.hpp"
#include "service/controller/controller.hpp"
#include "infra/panel_config.hpp"
#include "infra/config.hpp"
#include "infra/log.hpp"


void SetupPanels(net::io_context& main_ctx,
                 Controller& controller,
                 const Config& config,
                 app::dns::DNS& panel_dns_service) {
    if (config.panels.empty()) {
        return;
    }

    for (const auto& panel_config : config.panels) {
        for (int node_id : panel_config.NodeIDs.Values()) {
            api::Config api_config;
            api_config.Name = panel_config.Name;
            api_config.APIHost = panel_config.APIHost;
            api_config.Key = panel_config.Key;
            api_config.RequestTimeout = panel_config.RequestTimeout;
            api_config.NodeID = node_id;
            api_config.NodeType = panel_config.NodeType;

            PanelConfig node_panel_config = panel_config;
            node_panel_config.NodeIDs = PanelNodeIds::Single(node_id);

            auto panel = api::CreatePanelClient(main_ctx, api_config, panel_dns_service);
            controller.AddPanel(std::move(panel), node_panel_config);
            const PanelLogContext log_context{panel_config.Name, panel_config.APIHost,
                node_id, panel_config.NodeType};
            LOG_PANEL_INFO(log_context, "Panel node configured");
        }

    }
}

