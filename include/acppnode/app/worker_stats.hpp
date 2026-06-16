#pragma once

#include "acppnode/app/dns/stats.hpp"
#include "acppnode/app/stats.hpp"
#include "acppnode/common/memory_stats.hpp"

#include <cstddef>
#include <cstdint>

namespace acpp {

struct WorkerMemoryStats {
    size_t dns_entries = 0;
    size_t udp_sessions = 0;
    memory::BufferRecycleStats buffer_recycle;
};

struct WorkerRuntimeStatsSnapshot {
    WorkerMemoryStats memory;
    ::acpp::app::dns::DnsCacheStats dns_cache;
    StatsSnapshot stats;
    uint32_t active_connections = 0;
};

}  // namespace acpp
