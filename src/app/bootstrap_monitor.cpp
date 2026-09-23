#include "acppnode/app/bootstrap_monitor.hpp"
#include "acppnode/app/bootstrap_runtime.hpp"

#include "../common/awaitable_batch.hpp"
#include "../common/monitor_loop.hpp"

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

#include <algorithm>
#include <array>
#include <chrono>
#include <exception>
#include <fstream>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#include <psapi.h>
#endif

namespace acpp {

namespace {

struct MonitorContext {
    net::io_context& main_ctx;
    ShardedStats& stats;
    const std::vector<std::unique_ptr<Worker>>& workers;
    Controller& controller;
};

size_t ReadResidentMemoryBytes() {
#ifdef _WIN32
    PROCESS_MEMORY_COUNTERS_EX counters{};
    if (GetProcessMemoryInfo(
            GetCurrentProcess(),
            reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&counters),
            sizeof(counters))) {
        return static_cast<size_t>(counters.WorkingSetSize);
    }
#else
    std::ifstream status("/proc/self/status");
    std::string line;
    while (std::getline(status, line)) {
        if (line.starts_with("VmRSS:")) {
            return std::stoull(line.substr(6)) * 1024;
        }
    }
#endif
    return 0;
}

std::string FormatRate(double bytes_per_sec) {
    return acpp::FormatBytes(static_cast<uint64_t>(bytes_per_sec)) + "/s";
}

net::awaitable<std::vector<Worker::RuntimeStatsSnapshot>>
CollectWorkerRuntimeStats(const MonitorContext& ctx) {
    std::vector<Worker::RuntimeStatsSnapshot> snapshots(ctx.workers.size());
    std::vector<net::awaitable<void>> tasks;
    tasks.reserve(ctx.workers.size());
    for (size_t i = 0; i < ctx.workers.size(); ++i) {
        tasks.push_back(
            [](Worker* worker,
               Worker::RuntimeStatsSnapshot& out) -> net::awaitable<void> {
                out = co_await worker->PostTask(
                    worker->CollectRuntimeStatsTask());
            }(ctx.workers[i].get(), snapshots[i])
        );
    }
    co_await RunAwaitableBatch(
        ctx.main_ctx.get_executor(), std::move(tasks));
    co_return snapshots;
}

net::awaitable<void> CollectWorkerHeaps(const MonitorContext& ctx, bool force) {
    std::vector<net::awaitable<void>> tasks;
    tasks.reserve(ctx.workers.size());
    for (const auto& worker : ctx.workers) {
        tasks.push_back(
            [](Worker* owner, bool burst) -> net::awaitable<void> {
                co_await owner->PostTask(owner->CollectHeapTask(burst));
            }(worker.get(), force));
    }
    co_await RunAwaitableBatch(ctx.main_ctx.get_executor(), std::move(tasks));
    // The control thread may also hold short-lived PMR allocations.
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

net::awaitable<void> RuntimeSamplingLoop(
    const MonitorContext& ctx) {
    net::steady_timer timer(ctx.main_ctx);
    [[maybe_unused]] uint32_t last_sample_total_conns = 0;
    [[maybe_unused]] uint64_t last_force_collect_total_connections = 0;
    [[maybe_unused]] bool churn_collect_baseline_set = false;
    [[maybe_unused]] auto last_force_collect_at = steady_clock::time_point{};
    [[maybe_unused]] auto last_steady_collect_at = steady_clock::time_point{};
    auto last_log_flush_at = steady_clock::time_point{};
    while (true) {
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
            constexpr auto kSteadyCollectInterval = std::chrono::seconds(10);
            constexpr auto kIdleCollectInterval = std::chrono::seconds(1);

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
            const auto steady_interval = total_conns == 0
                ? kIdleCollectInterval : kSteadyCollectInterval;
            const bool steady_collect_due =
                last_steady_collect_at.time_since_epoch().count() == 0 ||
                now - last_steady_collect_at >= steady_interval;

            if (((burst_drain || newly_idle) && cooldown_ok) || churn_collect_due) {
                const char* reason =
                    churn_collect_due ? "churn" : (newly_idle ? "idle" : "burst-drain");
                LOG_INFO("mem-collect force reason={} conn={} churn={}",
                         reason, total_conns, churn_since_force);
                try {
                    co_await CollectWorkerHeaps(ctx, true);
                } catch (const std::exception& error) {
                    LOG_WARN("Worker heap collection skipped: {}", error.what());
                }
                last_force_collect_at = now;
                last_steady_collect_at = now;
                last_force_collect_total_connections = aggregate_stats.connections_total;
            } else if (steady_collect_due) {
                try {
                    co_await CollectWorkerHeaps(ctx, false);
                } catch (const std::exception& error) {
                    LOG_WARN("Worker heap collection skipped: {}", error.what());
                }
                last_steady_collect_at = now;
            }

            last_sample_total_conns = total_conns;
        }
        {
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

net::awaitable<void> RuntimeStatsOutputLoop(
    const MonitorContext& ctx) {
    net::steady_timer timer(ctx.main_ctx);
    while (true) {
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

        const double mem_mb = static_cast<double>(ReadResidentMemoryBytes()) / (1024.0 * 1024.0);

        size_t total_udp_sessions = 0;
        size_t pool_mapped_bytes = 0;
        size_t pool_direct_bytes = 0;
        size_t pool_idle_bytes = 0;
        size_t pool_chunks = 0;
        for (const auto& worker_snapshot : worker_snapshots) {
            total_udp_sessions += worker_snapshot.memory.udp_sessions;
            pool_mapped_bytes += worker_snapshot.memory.pool_mapped_bytes;
            pool_direct_bytes += worker_snapshot.memory.pool_direct_bytes;
            pool_idle_bytes += worker_snapshot.memory.pool_idle_bytes;
            pool_chunks += worker_snapshot.memory.pool_chunks;
        }
        const auto user_stats = proxyman::inbound::UserStore::GetStats();
        LOG_INFO(
            "runtime conn={} mem={:.1f}MB pool_mapped={}MB pool_direct={}MB pool_idle={}KB pool_chunks={} traffic_in={} traffic_out={} rate_down={} rate_up={} dns_hit={:.0f}% dns_l1={}/{} dns_l2={}/{} udp_sessions={} users={}",
            total_conns,
            mem_mb,
            pool_mapped_bytes / (1024 * 1024),
            pool_direct_bytes / (1024 * 1024),
            pool_idle_bytes / 1024,
            pool_chunks,
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

void ReportMonitorExit(std::string_view name, std::exception_ptr failure) {
    if (!failure) {
        LOG_WARN("runtime monitor loop={} stopped", name);
        return;
    }
    try {
        std::rethrow_exception(failure);
    } catch (const std::exception& error) {
        LOG_ERROR("runtime monitor loop={} failed: {}", name, error.what());
    } catch (...) {
        LOG_ERROR("runtime monitor loop={} failed with unknown exception", name);
    }
}

}  // namespace

struct RuntimeMonitor::Impl {
    explicit Impl(const RuntimeContext& runtime_context) {
        const MonitorContext ctx{
            runtime_context.main_ctx, runtime_context.stats,
            runtime_context.workers, runtime_context.controller};
        loops = {
            std::make_shared<monitor_detail::MonitorLoop>(
                ctx.main_ctx.get_executor(), "sampling",
                [ctx] { return RuntimeSamplingLoop(ctx); }, ReportMonitorExit),
            std::make_shared<monitor_detail::MonitorLoop>(
                ctx.main_ctx.get_executor(), "stats-output",
                [ctx] { return RuntimeStatsOutputLoop(ctx); }, ReportMonitorExit),
        };
    }

    std::array<std::shared_ptr<monitor_detail::MonitorLoop>, 2> loops;
};

RuntimeMonitor::RuntimeMonitor(const RuntimeContext& ctx)
    : impl_(std::make_unique<Impl>(ctx)) {}

RuntimeMonitor::~RuntimeMonitor() = default;

void RuntimeMonitor::Start() {
    for (const auto& loop : impl_->loops) loop->Start();
}

}  // namespace acpp
