#include "acppnode/app/bootstrap_panels.hpp"

#include "acppnode/api/panel_factory.hpp"
#include "acppnode/service/controller/controller.hpp"
#include "acppnode/service/controller/config.hpp"
#include "acppnode/infra/config.hpp"
#include "acppnode/infra/log.hpp"

namespace acpp {

void SetupPanels(net::io_context& main_ctx,
                 Controller& controller,
                 const Config& config,
                 app::dns::DNS& panel_dns_service) {
    if (config.GetPanels().empty()) {
        return;
    }

    for (const auto& panel_config : config.GetPanels()) {
        for (int node_id : panel_config.NodeIDs.Values()) {
            api::Config api_config;
            api_config.Name = panel_config.Name;
            api_config.APIHost = panel_config.APIHost;
            api_config.Key = panel_config.Key;
            api_config.NodeID = node_id;
            api_config.NodeType = panel_config.NodeType;

            PanelConfig node_panel_config = panel_config;
            node_panel_config.NodeIDs = PanelNodeIds::Single(node_id);

            auto panel = api::CreatePanelClient(main_ctx, api_config, panel_dns_service);
            controller.AddPanel(std::move(panel), node_panel_config);
        }

        std::string node_ids_str;
        const auto node_ids = panel_config.NodeIDs.Values();
        for (size_t i = 0; i < node_ids.size(); ++i) {
            if (i > 0) node_ids_str += ", ";
            node_ids_str += std::to_string(node_ids[i]);
        }
        LOG_CONSOLE("panel ready name={} type={} host={} nodes=[{}]",
                    panel_config.Name, panel_config.NodeType,
                    panel_config.APIHost, node_ids_str);
    }
}

}  // namespace acpp
