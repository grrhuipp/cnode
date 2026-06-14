#include "acppnode/app/bootstrap_panels.hpp"

#include "acppnode/api/panel_factory.hpp"
#include "acppnode/service/controller/controller.hpp"
#include "acppnode/service/controller/config.hpp"
#include "acppnode/infra/config.hpp"
#include "acppnode/infra/log.hpp"

#include <stdexcept>

namespace acpp {

void SetupPanels(net::io_context& main_ctx,
                 Controller& controller,
                 const Config& config,
                 app::dns::DNS& panel_dns_service) {
    if (config.GetPanels().empty()) {
        return;
    }

    LOG_CONSOLE("Panels:");
    for (const auto& panel_config : config.GetPanels()) {
        if (!panel_config.Validate()) {
            throw std::runtime_error("invalid panel config");
        }
        for (int node_id : panel_config.NodeIDs) {
            api::Config api_config;
            api_config.Name = panel_config.Name;
            api_config.APIHost = panel_config.APIHost;
            api_config.Key = panel_config.Key;
            api_config.NodeID = node_id;
            api_config.NodeType = panel_config.NodeType;

            PanelConfig node_panel_config = panel_config;
            node_panel_config.NodeIDs = {node_id};

            auto panel = api::CreatePanelClient(main_ctx, api_config, panel_dns_service);
            controller.AddPanel(std::move(panel), node_panel_config);
        }

        std::string node_ids_str;
        for (size_t i = 0; i < panel_config.NodeIDs.size(); ++i) {
            if (i > 0) node_ids_str += ", ";
            node_ids_str += std::to_string(panel_config.NodeIDs[i]);
        }
        LOG_CONSOLE("  - {} [{}] ({}): nodes=[{}]",
                    panel_config.Name, panel_config.NodeType,
                    panel_config.APIHost, node_ids_str);
    }
}

}  // namespace acpp
