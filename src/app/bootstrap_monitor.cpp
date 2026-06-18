#include "acppnode/app/bootstrap_monitor.hpp"

#include "acppnode/common/allocator.hpp"
#include "acppnode/common/defaults.hpp"
#include "acppnode/common/memory_stats.hpp"
#include "acppnode/service/controller/controller.hpp"
#include "acppnode/core/naming.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/app/proxyman/inbound/user_store.hpp"
#include "acppnode/app/dns/dns.hpp"
#include "acppnode/app/stats.hpp"
#include "acppnode/app/worker.hpp"
#include "acppnode/app/worker_stats.hpp"
#include "acppnode/common/buf/multi_buffer.hpp"

#include <algorithm>
#include <chrono>
#include <fstream>

#ifdef _WIN32
#include <windows.h>
#include <psapi.h>
#endif

namespace acpp {

namespace {

struct ProcessMemory {
    size_t vm_size = 0;
    size_t vm_rss  = 0;

    static ProcessMemory Read() {
        ProcessMemory mem;
#ifdef _WIN32
        PROCESS_MEMORY_COUNTERS_EX counters{};
        if (GetProcessMemoryInfo(
                GetCurrentProcess(),
                reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&counters),
                sizeof(counters))) {
            mem.vm_size = static_cast<size_t>(counters.PrivateUsage);
            mem.vm_rss  = static_cast<size_t>(counters.WorkingSetSize);
        }
        return mem;
#else
        std::ifstream status("/proc/self/status");
        if (!status) return mem;
        std::string line;
        while (std::getline(status, line)) {
            if (line.compare(0, 7, "VmSize:") == 0)
                mem.vm_size = std::stoull(line.substr(7)) * 1024;
            else if (line.compare(0, 6, "VmRSS:") == 0)
                mem.vm_rss = std::stoull(line.substr(6)) * 1024;
        }
        return mem;
#endif
    }
};

std::string FormatRate(double bytes_per_sec) {
    return acpp::FormatBytes(static_cast<uint64_t>(bytes_per_sec)) + "/s";
}

net::awaitable<double> GetMemoryMBAsync() {
    ProcessMemory mem = ProcessMemory::Read();
    co_return static_cast<double>(mem.vm_rss) / (1024.0 * 1024.0);
}

net::awaitable<std::vector<Worker::RuntimeStatsSnapshot>>
CollectWorkerRuntimeStats(const RuntimeContext& ctx) {
    std::vector<Worker::RuntimeStatsSnapshot> snapshots(ctx.workers.size());
    std::vector<net::awaitable<void>> tasks;
    tasks.reserve(ctx.workers.size());
    for (size_t i = 0; i < ctx.workers.size(); ++i) {
        tasks.push_back(
            [](Worker* worker,
               Worker::RuntimeStatsSnapshot& out) -> net::awaitable<void> {
                out = co_await net::co_spawn(
                    worker->GetExecutor(),
                    worker->CollectRuntimeStatsTask(),
                    net::use_awaitable);
            }(ctx.workers[i].get(), snapshots[i])
        );
    }
    for (auto& task : tasks) {
        co_await std::move(task);
    }
    co_return snapshots;
}

net::awaitable<void> CollectWorkerHeaps(const RuntimeContext& ctx, bool force) {
    std::vector<net::awaitable<void>> tasks;
    tasks.reserve(ctx.workers.size());
    for (const auto& worker : ctx.workers) {
        tasks.push_back(
            [](Worker* worker, bool force) -> net::awaitable<void> {
                co_await net::co_spawn(
                    worker->GetExecutor(),
                    [force]() -> net::awaitable<void> {
                        memory::CollectCurrentThread(force);
                        buf::TrimThreadBufferRecycle(force);
                        co_return;
                    }(),
                    net::use_awaitable);
            }(worker.get(), force)
        );
    }
    for (auto& task : tasks) {
        co_await std::move(task);
    }

    if (force) {
        memory::CollectBurst();
    } else {
        memory::CollectSteady();
    }
}

StatsSnapshot AggregateWorkerStats(
    const std::vector<Worker::RuntimeStatsSnapshot>& worker_snapshots) {
    StatsSnapshot snapshot;
    for (const auto& worker_snapshot : worker_snapshots) {
        const auto& s = worker_snapshot.stats;
        snapshot.connections_total  += s.connections_total;
        snapshot.connections_active += s.connections_active;
        snapshot.bytes_in           += s.bytes_in;
        snapshot.bytes_out          += s.bytes_out;
        snapshot.errors             += s.errors;
    }
    return snapshot;
}

net::awaitable<void> RuntimeSamplingLoop(const RuntimeContext& ctx, RuntimeState& state) {
    net::steady_timer timer(ctx.main_ctx);
    [[maybe_unused]] uint32_t last_sample_total_conns = 0;
    [[maybe_unused]] uint64_t last_force_collect_total_connections = 0;
    [[maybe_unused]] bool churn_collect_baseline_set = false;
    [[maybe_unused]] auto last_force_collect_at = steady_clock::time_point{};
    [[maybe_unused]] auto last_steady_collect_at = steady_clock::time_point{};
    while (state.running) {
        auto worker_snapshots = co_await CollectWorkerRuntimeStats(ctx);
        auto aggregate_stats = AggregateWorkerStats(worker_snapshots);
        ctx.stats.SampleNow(aggregate_stats);
        constexpr auto kAsyncLogFlushInterval = std::chrono::seconds(5);
        if constexpr (memory::kAllocatorCollects) {
            constexpr uint32_t kForceCollectMinPrevConns = 4096;
            constexpr uint32_t kForceCollectDropFactor = 4;
            constexpr uint32_t kForceCollectConnFloor = 64;
            constexpr auto kForceCollectCooldown = std::chrono::seconds(5);
            constexpr uint64_t kChurnForceCollectConnections = 2048;
            constexpr uint32_t kChurnForceCollectMinConns = 512;
            constexpr auto kChurnForceCollectCooldown = std::chrono::seconds(60);
            constexpr uint32_t kSteadyCollectMinConns = 512;
            constexpr auto kSteadyCollectInterval = std::chrono::seconds(10);

            uint32_t total_conns = 0;
            for (const auto& worker_snapshot : worker_snapshots) {
                total_conns += worker_snapshot.active_connections;
            }

            uint32_t force_threshold = last_sample_total_conns / kForceCollectDropFactor;
            if (force_threshold < kForceCollectConnFloor) {
                force_threshold = kForceCollectConnFloor;
            }

            const bool burst_drain =
                last_sample_total_conns >= kForceCollectMinPrevConns &&
                total_conns <= force_threshold;
            const bool newly_idle = (total_conns == 0 && last_sample_total_conns > 0);
            const auto now = steady_clock::now();
            const bool cooldown_ok =
                last_force_collect_at.time_since_epoch().count() == 0 ||
                now - last_force_collect_at >= kForceCollectCooldown;
            if (!churn_collect_baseline_set) {
                last_force_collect_total_connections = aggregate_stats.connections_total;
                churn_collect_baseline_set = true;
            }
            const uint64_t churn_since_force =
                aggregate_stats.connections_total >= last_force_collect_total_connections
                    ? aggregate_stats.connections_total - last_force_collect_total_connections
                    : 0;
            const bool churn_collect_due =
                total_conns >= kChurnForceCollectMinConns &&
                churn_since_force >= kChurnForceCollectConnections &&
                (last_force_collect_at.time_since_epoch().count() == 0 ||
                 now - last_force_collect_at >= kChurnForceCollectCooldown);
            const bool steady_collect_due =
                total_conns >= kSteadyCollectMinConns &&
                (last_steady_collect_at.time_since_epoch().count() == 0 ||
                 now - last_steady_collect_at >= kSteadyCollectInterval);

            if (((burst_drain || newly_idle) && cooldown_ok) || churn_collect_due) {
                const char* reason =
                    churn_collect_due ? "churn" : (newly_idle ? "idle" : "burst-drain");
                LOG_INFO("mem-collect force reason={} conn={} churn={}",
                         reason, total_conns, churn_since_force);
                co_await CollectWorkerHeaps(ctx, true);
                last_force_collect_at = now;
                last_steady_collect_at = now;
                last_force_collect_total_connections = aggregate_stats.connections_total;
            } else if (steady_collect_due) {
                co_await CollectWorkerHeaps(ctx, false);
                last_steady_collect_at = now;
            }

            last_sample_total_conns = total_conns;
        }
        {
            static auto last_log_flush_at = steady_clock::time_point{};
            const auto flush_now = steady_clock::now();
            if (last_log_flush_at.time_since_epoch().count() == 0 ||
                flush_now - last_log_flush_at >= kAsyncLogFlushInterval) {
                Log::Flush();
                last_log_flush_at = flush_now;
            }
        }
        timer.expires_after(std::chrono::seconds(1));
        auto [ec] = co_await timer.async_wait(net::as_tuple(net::use_awaitable));
        if (ec) break;
    }
}

net::awaitable<void> RuntimeStatsOutputLoop(const RuntimeContext& ctx, RuntimeState& state) {
    net::steady_timer timer(ctx.main_ctx);
    while (state.running) {
        auto worker_snapshots = co_await CollectWorkerRuntimeStats(ctx);
        auto snapshot = ctx.stats.WithCurrentRate(AggregateWorkerStats(worker_snapshots));

        ::acpp::app::dns::DnsCacheStats dns_l1_stats;
        for (const auto& worker_snapshot : worker_snapshots) {
            dns_l1_stats.hits    += worker_snapshot.dns_cache.hits;
            dns_l1_stats.misses  += worker_snapshot.dns_cache.misses;
            dns_l1_stats.entries += worker_snapshot.dns_cache.entries;
            dns_l1_stats.capacity += worker_snapshot.dns_cache.capacity;
            dns_l1_stats.expired += worker_snapshot.dns_cache.expired;
        }
        const auto dns_l2_stats = app::dns::DNS::GetGlobalCacheStats();

        double dns_hit_rate = 0.0;
        uint64_t dns_total = dns_l1_stats.hits + dns_l1_stats.misses;
        if (dns_total > 0) {
            const uint64_t l2_hits_for_workers =
                std::min(dns_l2_stats.hits, dns_l1_stats.misses);
            dns_hit_rate = 100.0 * static_cast<double>(dns_l1_stats.hits + l2_hits_for_workers)
                                 / static_cast<double>(dns_total);
        }

        uint32_t total_conns = 0;
        for (const auto& worker_snapshot : worker_snapshots) {
            total_conns += worker_snapshot.active_connections;
        }

        double mem_mb = co_await GetMemoryMBAsync();

        size_t total_udp_sessions = 0;
        for (const auto& worker_snapshot : worker_snapshots) {
            total_udp_sessions += worker_snapshot.memory.udp_sessions;
        }
        const auto user_stats = proxyman::inbound::UserStore::GetStats();
        LOG_INFO(
            "runtime conn={} mem={:.1f}MB traffic_in={} traffic_out={} rate_down={} rate_up={} dns_hit={:.0f}% dns_l1={}/{} dns_l2={}/{} udp_sessions={} users={}",
            total_conns,
            mem_mb,
            acpp::FormatBytes(snapshot.bytes_in),
            acpp::FormatBytes(snapshot.bytes_out),
            FormatRate(snapshot.bytes_in_rate),
            FormatRate(snapshot.bytes_out_rate),
            dns_hit_rate,
            dns_l1_stats.entries,
            dns_l1_stats.capacity,
            dns_l2_stats.entries,
            dns_l2_stats.capacity,
            total_udp_sessions,
            user_stats.TotalUsers());

#ifdef CNODE_MEMORY_STATS
        const auto runtime_mem = memory::SnapshotRuntimeMemoryStats();
        LOG_DEBUG("runtime.memory async_stream={}/{} tcp_stream={}/{} tls_stream={}/{}",
                  runtime_mem.async_streams_live,
                  runtime_mem.async_streams_peak,
                  runtime_mem.tcp_streams_live,
                  runtime_mem.tcp_streams_peak,
                  runtime_mem.tls_streams_live,
                  runtime_mem.tls_streams_peak);

        memory::BufferRecycleStats buffer_recycle;
        for (const auto& worker_snapshot : worker_snapshots) {
            const auto& stats = worker_snapshot.memory.buffer_recycle;
            buffer_recycle.cache_depth += stats.cache_depth;
            buffer_recycle.cache_capacity += stats.cache_capacity;
            buffer_recycle.cache_high_water += stats.cache_high_water;
            buffer_recycle.pop_hits += stats.pop_hits;
            buffer_recycle.pop_misses += stats.pop_misses;
            buffer_recycle.push_hits += stats.push_hits;
            buffer_recycle.push_drops += stats.push_drops;
            buffer_recycle.trim_frees += stats.trim_frees;
        }
        LOG_DEBUG(
            "runtime.buffer_recycle depth={}/{} high={} pop_hit={} pop_miss={} push={} drop={} trim={}",
            buffer_recycle.cache_depth,
            buffer_recycle.cache_capacity,
            buffer_recycle.cache_high_water,
            buffer_recycle.pop_hits,
            buffer_recycle.pop_misses,
            buffer_recycle.push_hits,
            buffer_recycle.push_drops,
            buffer_recycle.trim_frees);

        memory::SmallAllocCacheStats small_alloc_cache;
        for (const auto& worker_snapshot : worker_snapshots) {
            const auto& stats = worker_snapshot.memory.small_alloc_cache;
            small_alloc_cache.cache_depth += stats.cache_depth;
            small_alloc_cache.cache_capacity += stats.cache_capacity;
            small_alloc_cache.cache_high_water += stats.cache_high_water;
            small_alloc_cache.pop_hits += stats.pop_hits;
            small_alloc_cache.pop_misses += stats.pop_misses;
            small_alloc_cache.push_hits += stats.push_hits;
            small_alloc_cache.push_drops += stats.push_drops;
            small_alloc_cache.trim_frees += stats.trim_frees;
        }
        LOG_DEBUG(
            "runtime.small_alloc_cache depth={}/{} high={} pop_hit={} pop_miss={} push={} drop={} trim={}",
            small_alloc_cache.cache_depth,
            small_alloc_cache.cache_capacity,
            small_alloc_cache.cache_high_water,
            small_alloc_cache.pop_hits,
            small_alloc_cache.pop_misses,
            small_alloc_cache.push_hits,
            small_alloc_cache.push_drops,
            small_alloc_cache.trim_frees);
#endif

        auto node_stats = ctx.controller.GetNodeStats();
        if (!node_stats.empty()) {
            size_t node_users = 0;
            size_t node_online = 0;
            uint64_t node_up = 0;
            uint64_t node_down = 0;
            for (const auto& ns : node_stats) {
                node_users += ns.total_users;
                node_online += ns.online_users;
                node_up += ns.bytes_up;
                node_down += ns.bytes_down;
                LOG_DEBUG(
                    "runtime.node name={} port={} network={} users={} online={} upload={} download={}",
                    naming::BuildPanelNodeStatsKey(ns.panel_name, ns.node_id),
                    ns.port,
                    ns.network,
                    ns.total_users,
                    ns.online_users,
                    acpp::FormatBytes(ns.bytes_up),
                    acpp::FormatBytes(ns.bytes_down));
            }
            LOG_INFO("runtime.nodes count={} users={} online={} upload={} download={}",
                     node_stats.size(),
                     node_users,
                     node_online,
                     acpp::FormatBytes(node_up),
                     acpp::FormatBytes(node_down));
        }

        timer.expires_after(std::chrono::seconds(defaults::kStatsOutputInterval));
        auto [ec] = co_await timer.async_wait(net::as_tuple(net::use_awaitable));
        if (ec) break;
    }
}

}  // namespace

void StartRuntimeMonitoring(const RuntimeContext& ctx, RuntimeState& state) {
    net::co_spawn(ctx.main_ctx.get_executor(), RuntimeSamplingLoop(ctx, state), net::detached);
    net::co_spawn(ctx.main_ctx.get_executor(), RuntimeStatsOutputLoop(ctx, state), net::detached);
}

}  // namespace acpp
