#include "outboundbuilder.hpp"

#include "acppnode/core/constants.hpp"
#include "acppnode/infra/log.hpp"

#include "../../app/proxyman/outbound/source_config.hpp"

namespace acpp::controller {

proxyman::outbound::PreparedOutboundConfig OutboundBuilder(
    const std::string& tag,
    const PanelConfig* panel_config,
    const api::NodeInfo& /*node_config*/) {
    std::string send_through = std::string(constants::binding::kAuto);
    std::string domain_strategy = std::string(constants::protocol::kAsIs);

    if (panel_config) {
        if (!panel_config->SendIP.empty()) {
            send_through = panel_config->SendIP;
        }
        if (panel_config->EnableDNS) {
            domain_strategy = panel_config->DNSType.empty()
                ? std::string(constants::protocol::kUseIP)
                : panel_config->DNSType;
        }
    }

    proxyman::outbound::OutboundSourceConfig source;
    source.tag = tag;
    source.protocol = std::string(constants::protocol::kFreedom);
    source.send_through = std::move(send_through);
    source.settings["domainStrategy"] = std::move(domain_strategy);

    auto prepared = proxyman::outbound::PrepareOutboundConfig(source);
    if (prepared) {
        return std::move(*prepared);
    }

    LOG_WARN("OutboundBuilder: outbound protocol '{}' is not registered",
             constants::protocol::kFreedom);
    proxyman::outbound::PreparedOutboundConfig fallback;
    fallback.tag = tag;
    fallback.protocol = std::string(constants::protocol::kFreedom);
    return fallback;
}

}  // namespace acpp::controller
