#include "outboundbuilder.hpp"

#include "acppnode/core/constants.hpp"
#include "../../proxy/freedom/freedom_outbound.hpp"

namespace acpp::controller {

proxyman::outbound::PreparedOutboundConfig OutboundBuilder(
    const std::string& tag,
    const PanelConfig& panel_config) {
    proxy::freedom::outbound::FreedomSettings settings;
    settings.send_through = panel_config.SendIP;
    settings.domain_strategy = panel_config.EnableDNS
        ? panel_config.DNSType : proxy::freedom::outbound::DomainStrategy::AsIs;
    return proxyman::outbound::PreparedOutboundConfig{
        .tag = tag,
        .protocol = std::string(constants::protocol::kFreedom),
        .create = proxy::freedom::outbound::PrepareOutbound(std::move(settings)),
    };
}

}  // namespace acpp::controller
