#pragma once

#include "acppnode/app/dns/config.hpp"
#include "acppnode/app/proxyman/inbound/prepared_config.hpp"
#include "acppnode/app/proxyman/outbound/prepared_config.hpp"
#include "acppnode/app/static_inbound_prepared_config.hpp"
#include "acppnode/infra/runtime_config_types.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace acpp {

struct WorkerRuntimeConfig {
    ::acpp::app::dns::Config dns;
    TimeoutsConfig timeouts;
    LimitsConfig limits;
    RoutingConfig routing;
    std::vector<StaticInboundRuntimeEntry> static_inbounds;
    std::vector<proxyman::outbound::PreparedOutboundConfig> outbounds;
    uint32_t workers = 1;
    uint32_t pressure_threshold = 1;
    uint32_t pressure_idle_timeout = 0;
};

}  // namespace acpp
