#include "outboundbuilder.hpp"

#include "acppnode/core/constants.hpp"
#include "acppnode/infra/log.hpp"

#include "../../app/proxyman/outbound/source_config.hpp"

namespace acpp::controller {

std::optional<proxyman::outbound::PreparedOutboundConfig> OutboundBuilder(
    const std::string& tag,
    const PanelConfig* panel_config,
    const api::NodeInfo& /*node_config*/) {
    std::string domain_strategy = std::string(constants::protocol::kAsIs);

    if (panel_config) {
        if (panel_config->EnableDNS) {
            domain_strategy = panel_config->DNSType.empty()
                ? std::string(constants::protocol::kUseIP)
                : panel_config->DNSType;
        }
    }

    proxyman::outbound::OutboundSourceConfig source;
    source.tag = tag;
    source.protocol = std::string(constants::protocol::kFreedom);
    source.send_through = panel_config
        ? panel_config->SendIP
        : OutboundBind::Auto();
    source.settings["domainStrategy"] = std::move(domain_strategy);

    auto prepared = proxyman::outbound::PrepareOutboundConfig(source);
    if (prepared) {
        return prepared;
    }

    LOG_WARN("OutboundBuilder: outbound protocol '{}' is not registered",
             constants::protocol::kFreedom);
    return std::nullopt;
}

}  // namespace acpp::controller
