#pragma once

#include "acppnode/app/stats.hpp"

#include <cstddef>
#include <cstdint>

namespace acpp {

struct WorkerMemoryStats {
    size_t udp_sessions = 0;
    size_t pool_mapped_bytes = 0;
    size_t pool_direct_bytes = 0;
    size_t pool_idle_bytes = 0;
    size_t pool_chunks = 0;
};

struct WorkerRuntimeStatsSnapshot {
    WorkerMemoryStats memory;
    StatsSnapshot stats;
    // Effective Worker load: max(physical transports, active dispatches).
    uint32_t active_connections = 0;
};

}  // namespace acpp
