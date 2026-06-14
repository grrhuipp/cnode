#pragma once

#include "acppnode/app/dns/stats.hpp"
#include "acppnode/app/stats.hpp"

#include <cstddef>
#include <cstdint>

namespace acpp {

struct WorkerMemoryStats {
    size_t dns_entries = 0;
    size_t dns_estimated_bytes = 0;
    size_t udp_sessions = 0;
    size_t udp_estimated_bytes = 0;
    size_t vmess_accounts = 0;
    size_t trojan_users = 0;
    size_t users_estimated_bytes = 0;
    size_t total_estimated_bytes = 0;
};

struct WorkerRuntimeStatsSnapshot {
    WorkerMemoryStats memory;
    ::acpp::app::dns::DnsCacheStats dns_cache;
    StatsSnapshot stats;
    uint32_t active_connections = 0;
};

}  // namespace acpp
