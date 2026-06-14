#pragma once

#include "acppnode/api/api.hpp"
#include "acppnode/app/port_binding.hpp"
#include "acppnode/app/proxyman/inbound/prepared_config.hpp"
#include "acppnode/service/controller/config.hpp"
#include "acppnode/proxy/sniff_config.hpp"
#include "acppnode/transport/internet/proxy_protocol_mode.hpp"
#include "acppnode/transport/internet/stream_settings.hpp"

#include <string>

namespace acpp::controller {

struct InboundBuild {
    std::string         protocol;
    std::string         tag;
    StreamSettings      stream_settings;
    SniffConfig         sniff;
    proxyman::inbound::BuildRequest handler_request;
    PortBinding         binding;
    ProxyProtocolMode   proxy_protocol = ProxyProtocolMode::Auto;
};

[[nodiscard]] InboundBuild InboundBuilder(const std::string& panel_name,
                                          const PanelConfig* panel_config,
                                          const api::NodeInfo& node_config);

}  // namespace acpp::controller
