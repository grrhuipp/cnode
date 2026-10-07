#pragma once

#include "acppnode/app/stats.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>

namespace acpp {

struct WorkerMemoryStats {
    size_t udp_sockets = 0;
    size_t pool_mapped_bytes = 0;
    size_t pool_direct_bytes = 0;
    size_t pool_idle_bytes = 0;
    size_t pool_chunks = 0;
};

// Sampled only on the owning Worker; passed to the control plane by value.
struct WorkerResourceStats {
    size_t udp_listeners = 0;
    size_t udp_receive_loops = 0;
    uint64_t udp_resource_drops = 0;
    size_t udp_associations = 0;
    size_t udp_closed_associations = 0;
    size_t udp_input_datagrams = 0;
    size_t udp_input_bytes = 0;
    size_t udp_reply_datagrams = 0;
    size_t udp_reply_bytes = 0;
    size_t udp_reply_senders = 0;
    size_t udp_native_dispatches = 0;
    size_t timeout_events = 0;
    size_t timeout_heap_entries = 0;
    size_t timeout_heap_capacity = 0;
    size_t timeout_event_buckets = 0;
    size_t timeout_ready_events = 0;
    size_t timeout_waiters = 0;
};

struct WorkerRuntimeStatsSnapshot {
    WorkerMemoryStats memory;
    std::optional<WorkerResourceStats> resources;
    StatsSnapshot stats;
    uint32_t worker_id = 0;
    // Effective Worker load: max(physical transports, active dispatches).
    uint32_t active_connections = 0;
};

}  // namespace acpp
