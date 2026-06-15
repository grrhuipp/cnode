#pragma once

#include "acppnode/app/dns/stats.hpp"
#include "acppnode/app/stats.hpp"

#include <cstddef>
#include <cstdint>

namespace acpp {

struct WorkerMemoryStats {
    size_t dns_entries = 0;
    size_t udp_sessions = 0;
};

struct WorkerRuntimeStatsSnapshot {
    WorkerMemoryStats memory;
    ::acpp::app::dns::DnsCacheStats dns_cache;
    StatsSnapshot stats;
    uint32_t active_connections = 0;
};

}  // namespace acpp
