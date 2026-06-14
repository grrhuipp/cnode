#include "outboundbuilder.hpp"

#include "acppnode/core/constants.hpp"
#include "acppnode/proxy/freedom/freedom_outbound.hpp"

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

    freedom::outbound::FreedomSettings settings;
    settings.send_through = std::move(send_through);
    settings.domain_strategy = std::move(domain_strategy);

    proxyman::outbound::PreparedOutboundConfig outbound;
    outbound.tag = tag;
    outbound.protocol = std::string(constants::protocol::kFreedom);
    outbound.create =
        [tag, settings = std::move(settings)](
            net::io_context& /*io_context*/,
            app::dns::DNS& dns,
            UDPSessionManager* udp_mgr,
            std::chrono::seconds dial_timeout) -> std::unique_ptr<Outbound> {
            return std::make_unique<freedom::outbound::Handler>(
                tag, settings, dns, udp_mgr, dial_timeout);
        };
    return outbound;
}

}  // namespace acpp::controller
