#pragma once

#include "app/proxyman/inbound/prepared_config.hpp"
#include "app/proxyman/outbound/prepared_config.hpp"
#include "infra/runtime_config_types.hpp"

#include <cstdint>
#include <vector>


struct WorkerRuntimeConfig {
    TimeoutsConfig timeouts;
    LimitsConfig limits;
    RoutingConfig routing;
    std::vector<proxyman::outbound::PreparedOutboundConfig> outbounds;
    uint32_t workers = 0;
    uint32_t pressure_threshold = 1;
    uint32_t pressure_idle_timeout = 0;
};

