#include "acppnode/app/bootstrap_monitor.hpp"

#include "acppnode/common/allocator.hpp"
#include "acppnode/app/panel_sync.hpp"
#include "acppnode/core/naming.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/app/stats.hpp"
#include "acppnode/app/worker.hpp"

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

cobalt::task<double> GetMemoryMBAsync(net::any_io_executor /*exec*/) {
    ProcessMemory mem = ProcessMemory::Read();
    co_return static_cast<double>(mem.vm_rss) / (1024.0 * 1024.0);
}

void StartRuntimeSampling(const RuntimeContext& ctx, std::atomic<bool>& running) {
    uint32_t last_sample_total_conns = 0;
#ifdef USE_MIMALLOC
    auto last_force_collect_at = steady_clock::time_point{};
    auto last_steady_collect_at = steady_clock::time_point{};
#endif
    auto sample_coro = [&running, &ctx, &last_sample_total_conns
#ifdef USE_MIMALLOC
        , &last_force_collect_at, &last_steady_collect_at
#endif
        ](net::steady_timer& timer) -> cobalt::task<void> {
        while (running) {
            ctx.stats.SampleNow();
            constexpr auto kAsyncLogFlushInterval = std::chrono::seconds(5);
#ifdef USE_MIMALLOC
            constexpr uint32_t kForceCollectMinPrevConns = 4096;
            constexpr uint32_t kForceCollectDropFactor = 8;
            constexpr uint32_t kForceCollectConnFloor = 64;
            constexpr auto kForceCollectCooldown = std::chrono::seconds(3);
            constexpr uint32_t kSteadyCollectMinConns = 2048;
            constexpr auto kSteadyCollectInterval = std::chrono::seconds(5);

            uint32_t total_conns = 0;
            for (const auto& w : ctx.workers) {
                total_conns += w->GetActiveConnectionCount();
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

            if ((burst_drain || newly_idle) && cooldown_ok) {
                memory::CollectBurst();
                last_force_collect_at = now;
                last_steady_collect_at = now;
            } else if (steady_collect_due) {
                memory::CollectSteady();
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
            auto [ec] = co_await timer.async_wait(net::as_tuple(cobalt::use_op));
            if (ec) break;
        }
    };
    net::steady_timer sample_timer(ctx.main_ctx);
    cobalt::spawn(ctx.main_ctx.get_executor(), sample_coro(sample_timer), net::detached);
}

void StartRuntimeStatsOutput(const RuntimeContext& ctx, std::atomic<bool>& running) {
    auto stats_coro = [&running, &ctx](net::steady_timer& timer) -> cobalt::task<void> {
        while (running) {
            auto snapshot = ctx.stats.AggregateWithRate();

            DnsCacheStats dns_stats;
            if (!ctx.workers.empty() && ctx.workers[0]->GetDnsService()) {
                dns_stats = ctx.workers[0]->GetDnsService()->GetCacheStats();
            }

            double dns_hit_rate = 0.0;
            uint64_t dns_total = dns_stats.hits + dns_stats.misses;
            if (dns_total > 0) {
                dns_hit_rate = 100.0 * static_cast<double>(dns_stats.hits)
                                     / static_cast<double>(dns_total);
            }

            uint32_t total_conns = 0;
            for (const auto& w : ctx.workers) {
                total_conns += w->GetActiveConnectionCount();
            }

            double mem_mb = co_await GetMemoryMBAsync(ctx.main_ctx.get_executor());

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
                for (const auto& worker : ctx.workers) {
                    auto m = worker->GetMemoryStats();
                    total_mem.dns_estimated_bytes   += m.dns_estimated_bytes;
                    total_mem.udp_estimated_bytes   += m.udp_estimated_bytes;
                    total_mem.users_estimated_bytes += m.users_estimated_bytes;
                }
                LOG_INFO("mem: dns={:.0f}KB udp={:.0f}KB usr={:.0f}KB | RSS={:.1f}MB",
                         total_mem.dns_estimated_bytes / 1024.0,
                         total_mem.udp_estimated_bytes / 1024.0,
                         total_mem.users_estimated_bytes / 1024.0,
                         proc_mem.vm_rss / (1024.0 * 1024.0));
            }

            auto node_stats = ctx.sync_manager.GetNodeStats();
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
            auto [ec] = co_await timer.async_wait(net::as_tuple(cobalt::use_op));
            if (ec) break;
        }
    };
    net::steady_timer stats_timer(ctx.main_ctx);
    cobalt::spawn(ctx.main_ctx.get_executor(), stats_coro(stats_timer), net::detached);
}

}  // namespace

void StartRuntimeMonitoring(const RuntimeContext& ctx, std::atomic<bool>& running) {
    StartRuntimeSampling(ctx, running);
    StartRuntimeStatsOutput(ctx, running);
}

}  // namespace acpp
