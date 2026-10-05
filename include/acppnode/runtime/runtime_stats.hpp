#pragma once

#include "acppnode/app/stats.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>

namespace acpp {

struct RuntimeMemoryStats {
    size_t udp_sockets = 0;
};

// Sampled only on the owning Runtime; passed to the control plane by value.
struct RuntimeResourceStats {
    size_t udp_listeners = 0;
    size_t udp_receive_loops = 0;
    uint64_t udp_resource_drops = 0;
    size_t udp_associations = 0;
    size_t udp_retiring_associations = 0;
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

struct RuntimeStatsSnapshot {
    RuntimeMemoryStats memory;
    std::optional<RuntimeResourceStats> resources;
    StatsSnapshot stats;
    // Effective Runtime load: max(physical transports, active dispatches).
    uint32_t active_connections = 0;
};

}  // namespace acpp
