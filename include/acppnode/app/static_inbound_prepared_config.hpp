#pragma once

#include "acppnode/app/proxyman/inbound/prepared_config.hpp"
#include "acppnode/proxy/sniff_config.hpp"
#include "acppnode/transport/internet/stream_settings.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace acpp {

struct StaticInboundRuntimeEntry {
    std::string protocol;
    std::string tag;
    std::vector<std::string> all_tags;
    uint16_t port = 0;
    std::string listen;
    StreamSettings stream_settings;
    SniffConfig sniffing;
    std::string outbound_tag;
    proxyman::inbound::BuildRequest build_request;
};

}  // namespace acpp
