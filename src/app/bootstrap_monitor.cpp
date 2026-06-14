#include "acppnode/app/bootstrap_monitor.hpp"

#include "acppnode/common/allocator.hpp"
#include "acppnode/common/defaults.hpp"
#include "acppnode/common/memory_stats.hpp"
#include "acppnode/service/controller/controller.hpp"
#include "acppnode/core/naming.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/app/stats.hpp"
#include "acppnode/app/worker.hpp"
#include "acppnode/app/worker_stats.hpp"
#include "acppnode/common/buf/multi_buffer.hpp"

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

#ifdef USE_MIMALLOC
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
#endif

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
#ifdef USE_MIMALLOC
    uint32_t last_sample_total_conns = 0;
    auto last_force_collect_at = steady_clock::time_point{};
    auto last_steady_collect_at = steady_clock::time_point{};
#endif
    while (state.running) {
        auto worker_snapshots = co_await CollectWorkerRuntimeStats(ctx);
        ctx.stats.SampleNow(AggregateWorkerStats(worker_snapshots));
        constexpr auto kAsyncLogFlushInterval = std::chrono::seconds(5);
#ifdef USE_MIMALLOC
        constexpr uint32_t kForceCollectMinPrevConns = 4096;
        constexpr uint32_t kForceCollectDropFactor = 4;
        constexpr uint32_t kForceCollectConnFloor = 64;
        constexpr auto kForceCollectCooldown = std::chrono::seconds(1);
        constexpr uint32_t kSteadyCollectMinConns = 512;
        constexpr auto kSteadyCollectInterval = std::chrono::seconds(2);
        constexpr uint32_t kRssGuardMinConns = 256;
        constexpr size_t kTargetRssPerConnBytes = 50 * 1024;
        constexpr auto kRssGuardForceCollectInterval = std::chrono::seconds(3);

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
        const bool steady_collect_due =
            total_conns >= kSteadyCollectMinConns &&
            (last_steady_collect_at.time_since_epoch().count() == 0 ||
             now - last_steady_collect_at >= kSteadyCollectInterval);
        const auto proc_mem = ProcessMemory::Read();
        const bool rss_per_conn_over_target =
            total_conns >= kRssGuardMinConns &&
            proc_mem.vm_rss / static_cast<size_t>(total_conns) > kTargetRssPerConnBytes;
        const bool rss_guard_collect_due =
            rss_per_conn_over_target &&
            (last_force_collect_at.time_since_epoch().count() == 0 ||
             now - last_force_collect_at >= kRssGuardForceCollectInterval);

        if (((burst_drain || newly_idle) && cooldown_ok) || rss_guard_collect_due) {
            co_await CollectWorkerHeaps(ctx, true);
            last_force_collect_at = now;
            last_steady_collect_at = now;
        } else if (steady_collect_due) {
            co_await CollectWorkerHeaps(ctx, false);
            last_steady_collect_at = now;
        }

        last_sample_total_conns = total_conns;
#endif
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

        ::acpp::app::dns::DnsCacheStats dns_stats;
        for (const auto& worker_snapshot : worker_snapshots) {
            dns_stats.hits    += worker_snapshot.dns_cache.hits;
            dns_stats.misses  += worker_snapshot.dns_cache.misses;
            dns_stats.entries += worker_snapshot.dns_cache.entries;
            dns_stats.expired += worker_snapshot.dns_cache.expired;
        }

        double dns_hit_rate = 0.0;
        uint64_t dns_total = dns_stats.hits + dns_stats.misses;
        if (dns_total > 0) {
            dns_hit_rate = 100.0 * static_cast<double>(dns_stats.hits)
                                 / static_cast<double>(dns_total);
        }

        uint32_t total_conns = 0;
        for (const auto& worker_snapshot : worker_snapshots) {
            total_conns += worker_snapshot.active_connections;
        }

        double mem_mb = co_await GetMemoryMBAsync();

        LOG_INFO("conn={} mem={:.1f}MB in={} out={} rate={}↓/{}↑ dns={:.0f}%",
                 total_conns, mem_mb,
                 acpp::FormatBytes(snapshot.bytes_in),
                 acpp::FormatBytes(snapshot.bytes_out),
                 FormatRate(snapshot.bytes_in_rate),
                 FormatRate(snapshot.bytes_out_rate),
                 dns_hit_rate);

        {
            Worker::MemoryStats total_mem{};
            auto proc_mem = ProcessMemory::Read();
            for (const auto& worker_snapshot : worker_snapshots) {
                const auto& m = worker_snapshot.memory;
                total_mem.dns_estimated_bytes   += m.dns_estimated_bytes;
                total_mem.udp_estimated_bytes   += m.udp_estimated_bytes;
                total_mem.users_estimated_bytes += m.users_estimated_bytes;
            }
            LOG_INFO("mem: dns={:.0f}KB udp={:.0f}KB usr={:.0f}KB | RSS={:.1f}MB",
                     total_mem.dns_estimated_bytes / 1024.0,
                     total_mem.udp_estimated_bytes / 1024.0,
                     total_mem.users_estimated_bytes / 1024.0,
                     proc_mem.vm_rss / (1024.0 * 1024.0));
#ifdef CNODE_MEMORY_STATS
            const auto runtime_mem = memory::SnapshotRuntimeMemoryStats();
            LOG_INFO("mem-live: buffer={}/{} ({:.1f}MB live) async_stream={}/{} tcp_stream={}/{}",
                     runtime_mem.buffers_live,
                     runtime_mem.buffers_peak,
                     runtime_mem.buffers_live * sizeof(Buffer) / (1024.0 * 1024.0),
                     runtime_mem.async_streams_live,
                     runtime_mem.async_streams_peak,
                     runtime_mem.tcp_streams_live,
                     runtime_mem.tcp_streams_peak);
#endif
        }

        auto node_stats = ctx.controller.GetNodeStats();
        if (!node_stats.empty()) {
            LOG_INFO("┌────────────┬───────┬─────────┬────────┬────────┬──────────┬──────────┐");
            LOG_INFO("│ Node       │ Port  │ Network │ Users  │ Online │ ↑ Up     │ ↓ Down   │");
            LOG_INFO("├────────────┼───────┼─────────┼────────┼────────┼──────────┼──────────┤");
            for (const auto& ns : node_stats) {
                std::string name = naming::BuildPanelNodeStatsKey(ns.panel_name, ns.node_id);
                if (name.size() > 10) name = name.substr(0, 10);
                LOG_INFO("│ {:<10} │ {:>5} │ {:<7} │ {:>6} │ {:>6} │ {:>8} │ {:>8} │",
                         name, ns.port, ns.network, ns.total_users,
                         ns.online_users,
                         acpp::FormatBytes(ns.bytes_up),
                         acpp::FormatBytes(ns.bytes_down));
            }
            LOG_INFO("└────────────┴───────┴─────────┴────────┴────────┴──────────┴──────────┘");
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
