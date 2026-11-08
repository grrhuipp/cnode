#include "app/bootstrap_monitor.hpp"
#include "app/bootstrap_runtime.hpp"

#include "../common/awaitable_batch.hpp"
#include "../common/monitor_loop.hpp"
#include "../common/process_resources.hpp"

#include "common/allocator.hpp"
#include "common/defaults.hpp"
#include "common/memory_stats.hpp"
#include "service/controller/controller.hpp"
#include "infra/log.hpp"
#include "app/proxyman/inbound/user_store.hpp"
#include "app/dns/dns.hpp"
#include "app/dns/dns_worker.hpp"
#include "app/stats.hpp"
#include "app/worker.hpp"
#include "app/worker_stats.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <cmath>
#include <exception>
#include <fstream>
#include <limits>
#include <string_view>
#include <vector>


namespace {

struct MonitorContext {
    net::io_context& main_ctx;
    ShardedStats& stats;
    const std::vector<std::unique_ptr<Worker>>& workers;
    Controller& controller;
    app::dns::DNSWorker& dns_worker;
    bool stopping = false;

    void ThrowIfStopping() const {
        if (stopping) throw IoSystemError(net::error::operation_aborted);
    }
};

size_t ReadResidentMemoryBytes() noexcept {
    try {
        std::ifstream status("/proc/self/status");
        std::string line;
        while (std::getline(status, line)) {
            if (!line.starts_with("VmRSS:")) continue;
            std::string_view text(line.data() + 6, line.size() - 6);
            while (!text.empty() && (text.front() == ' ' || text.front() == '\t')) {
                text.remove_prefix(1);
            }
            size_t kb = 0;
            const auto [ptr, ec] = std::from_chars(
                text.data(), text.data() + text.size(), kb);
            if (ec != std::errc{} || ptr == text.data() ||
                kb > std::numeric_limits<size_t>::max() / 1024) {
                return 0;
            }
            return kb * 1024;
        }
    } catch (...) {
    }
    return 0;
}

std::string FormatRate(double bytes_per_sec) {
    if (!std::isfinite(bytes_per_sec) || bytes_per_sec <= 0.0) {
        return ::FormatBytes(0) + "/s";
    }
    constexpr double kMaxBytes =
        static_cast<double>(std::numeric_limits<uint64_t>::max());
    const uint64_t rate = bytes_per_sec >= kMaxBytes
        ? std::numeric_limits<uint64_t>::max()
        : static_cast<uint64_t>(bytes_per_sec);
    return ::FormatBytes(rate) + "/s";
}

net::awaitable<std::vector<WorkerRuntimeStatsSnapshot>>
CollectWorkerRuntimeStats(const MonitorContext& ctx, bool include_resources) {
    ctx.ThrowIfStopping();
    std::vector<WorkerRuntimeStatsSnapshot> snapshots(ctx.workers.size());
    std::vector<net::awaitable<void>> tasks;
    tasks.reserve(ctx.workers.size());
    for (size_t i = 0; i < ctx.workers.size(); ++i) {
        tasks.push_back(
            [](const MonitorContext& context, Worker* worker,
               WorkerRuntimeStatsSnapshot& out,
               bool collect_resources) -> net::awaitable<void> {
                context.ThrowIfStopping();
                out = co_await worker->PostTask(worker->CollectRuntimeStats(collect_resources));
            }(ctx, ctx.workers[i].get(), snapshots[i], include_resources)
        );
    }
    co_await RunAwaitableBatch(
        ctx.main_ctx.get_executor(), std::move(tasks));
    ctx.ThrowIfStopping();
    co_return snapshots;
}

net::awaitable<void> CollectWorkerHeaps(const MonitorContext& ctx) {
    ctx.ThrowIfStopping();
    std::vector<net::awaitable<void>> tasks;
    tasks.reserve(ctx.workers.size());
    for (const auto& worker : ctx.workers) {
        tasks.push_back(
            [](const MonitorContext& context, Worker* owner) -> net::awaitable<void> {
                context.ThrowIfStopping();
                co_await owner->PostCall([owner] { owner->CollectHeap(); });
            }(ctx, worker.get()));
    }
    co_await RunAwaitableBatch(ctx.main_ctx.get_executor(), std::move(tasks));
    ctx.ThrowIfStopping();
    // The control thread may also hold short-lived PMR allocations.
    memory::CollectBurst();
}

StatsSnapshot AggregateWorkerStats(
    const std::vector<WorkerRuntimeStatsSnapshot>& worker_snapshots) {
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
    uint32_t last_sample_total_conns = 0;
    uint64_t last_force_collect_total_connections = 0;
    bool churn_collect_baseline_set = false;
    auto last_force_collect_at = steady_clock::time_point{};
    auto last_log_flush_at = steady_clock::time_point{};
    while (true) {
        auto worker_snapshots = co_await CollectWorkerRuntimeStats(ctx, false);
        auto aggregate_stats = AggregateWorkerStats(worker_snapshots);
        ctx.stats.SampleNow(aggregate_stats);
        constexpr auto kAsyncLogFlushInterval = std::chrono::seconds(5);
        {
            constexpr uint32_t kForceCollectMinPrevConns = 4096;
            constexpr uint32_t kForceCollectDropFactor = 4;
            constexpr uint32_t kForceCollectConnFloor = 64;
            constexpr auto kForceCollectCooldown = std::chrono::seconds(5);
            constexpr uint64_t kChurnForceCollectConnections = 2048;
            constexpr uint32_t kChurnForceCollectMinConns = 512;
            constexpr auto kChurnForceCollectCooldown = std::chrono::seconds(60);

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

            if (((burst_drain || newly_idle) && cooldown_ok) || churn_collect_due) {
                const char* reason =
                    churn_collect_due ? "churn" : (newly_idle ? "idle" : "burst-drain");
                LOG_CONSOLE("Forcing worker heap collection: reason={} conn={} churn={}",
                         reason, total_conns, churn_since_force);
                try {
                    co_await CollectWorkerHeaps(ctx);
                } catch (const std::exception& error) {
                    ctx.ThrowIfStopping();
                    LOG_CONSOLE_WARN("Worker heap collection skipped: {}", error.what());
                }
                last_force_collect_at = now;
                last_force_collect_total_connections = aggregate_stats.connections_total;
                last_sample_total_conns = total_conns;
            } else if ((burst_drain || newly_idle) && !cooldown_ok) {
                last_sample_total_conns = std::max(last_sample_total_conns, total_conns);
            } else {
                last_sample_total_conns = total_conns;
            }
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
        auto worker_snapshots = co_await CollectWorkerRuntimeStats(ctx, true);
        auto snapshot = ctx.stats.WithCurrentRate(AggregateWorkerStats(worker_snapshots));

        const auto dns_stats = co_await ctx.dns_worker.GetCacheStats();
        ctx.ThrowIfStopping();
        const uint64_t dns_total = dns_stats.hits + dns_stats.misses;
        const double dns_hit_rate = dns_total > 0
            ? 100.0 * static_cast<double>(dns_stats.hits) / static_cast<double>(dns_total)
            : 0.0;

        uint32_t total_conns = 0;
        for (const auto& worker_snapshot : worker_snapshots) {
            total_conns += worker_snapshot.active_connections;
        }

        const double mem_mb = static_cast<double>(ReadResidentMemoryBytes()) / (1024.0 * 1024.0);

        size_t total_udp_sockets = 0;
        size_t pool_mapped_bytes = 0;
        size_t pool_direct_bytes = 0;
        size_t pool_idle_bytes = 0;
        size_t pool_chunks = 0;
        for (const auto& worker_snapshot : worker_snapshots) {
            total_udp_sockets += worker_snapshot.memory.udp_sockets;
            pool_mapped_bytes += worker_snapshot.memory.pool_mapped_bytes;
            pool_direct_bytes += worker_snapshot.memory.pool_direct_bytes;
            pool_idle_bytes += worker_snapshot.memory.pool_idle_bytes;
            pool_chunks += worker_snapshot.memory.pool_chunks;
        }
        const auto total_users = proxyman::inbound::UserStore::TotalUsers();
        LOG_CONSOLE("Runtime activity: conn={} users={} udp_sockets={}",
                    total_conns, total_users, total_udp_sockets);
        LOG_CONSOLE("Runtime memory: resident={:.1f}MB pool_mapped={}MB pool_direct={}MB pool_idle={}KB pool_chunks={} pmr_remote_frees={}",
                    mem_mb, pool_mapped_bytes / (1024 * 1024),
                    pool_direct_bytes / (1024 * 1024), pool_idle_bytes / 1024,
                    pool_chunks, memory::RemoteFreeCount());
        LOG_CONSOLE("Runtime traffic: traffic_in={} traffic_out={} rate_down={} rate_up={}",
                    ::FormatBytes(snapshot.bytes_in), ::FormatBytes(snapshot.bytes_out),
                    FormatRate(snapshot.bytes_in_rate), FormatRate(snapshot.bytes_out_rate));
        LOG_CONSOLE("Runtime DNS cache: dns_hit={:.0f}% dns_cache={}/{}",
                    dns_hit_rate, dns_stats.entries, dns_stats.capacity);

        const auto descriptors = ReadProcessDescriptors();
        LOG_CONSOLE("Process descriptors: fds={} soft_limit={}",
                 descriptors.open ? std::to_string(*descriptors.open) : "unknown",
                 descriptors.soft_limit ? std::to_string(*descriptors.soft_limit)
                     : descriptors.soft_limit_unlimited ? "unlimited" : "unknown");
        for (const auto& worker : worker_snapshots) {
            const auto& r = *worker.resources;
            LOG_CONSOLE("Worker activity: id={} conn={} udp_sockets={} timeout_heap={}/{} timeout_waiters={}",
                        worker.worker_id, worker.active_connections, worker.memory.udp_sockets,
                        r.timeout_events, r.timeout_heap_capacity, r.timeout_waiters);
            LOG_CONSOLE("Worker memory: id={} pool_mapped={} pool_direct={} pool_idle={} pool_chunks={}",
                        worker.worker_id, worker.memory.pool_mapped_bytes, worker.memory.pool_direct_bytes,
                        worker.memory.pool_idle_bytes, worker.memory.pool_chunks);
            LOG_CONSOLE("Worker UDP resources: id={} udp_listeners={} udp_receive_loops={} udp_resource_drops={} udp_associations={} udp_closed={} udp_reply_senders={}",
                        worker.worker_id, r.udp_listeners, r.udp_receive_loops, r.udp_resource_drops,
                        r.udp_associations, r.udp_closed_associations, r.udp_reply_senders);
            LOG_CONSOLE("Worker UDP traffic: id={} udp_input_packets={} udp_input_bytes={} udp_reply_packets={} udp_reply_bytes={} udp_native_dispatches={}",
                        worker.worker_id, r.udp_input_datagrams, r.udp_input_bytes,
                        r.udp_reply_datagrams, r.udp_reply_bytes, r.udp_native_dispatches);
        }

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
                const PanelLogContext log_context{ns.panel_name, ns.panel_host, ns.node_id, ns.node_type};
                LOG_PANEL_DEBUG(log_context,
                    "Node activity: port={} network={} users={} online={} upload={} download={}",
                    ns.port,
                    ns.network,
                    ns.total_users,
                    ns.online_users,
                    ::FormatBytes(ns.bytes_up),
                    ::FormatBytes(ns.bytes_down));
            }
            LOG_CONSOLE("Panel node totals: count={} users={} online={} upload={} download={}",
                     node_stats.size(),
                     node_users,
                     node_online,
                     ::FormatBytes(node_up),
                     ::FormatBytes(node_down));
        }

        timer.expires_after(std::chrono::seconds(defaults::kStatsOutputInterval));
        auto [ec] = co_await timer.async_wait(net::as_tuple(net::use_awaitable));
        if (ec) break;
    }
}

void ReportMonitorExit(std::string_view name, std::exception_ptr failure) {
    if (!failure) {
        LOG_CONSOLE_WARN("Runtime monitor stopped unexpectedly: loop={}", name);
        return;
    }
    try {
        std::rethrow_exception(failure);
    } catch (const std::exception& error) {
        LOG_CONSOLE_ERROR("Runtime monitor failed: loop={} reason={}", name, error.what());
    } catch (...) {
        LOG_CONSOLE_ERROR("Runtime monitor failed: loop={} reason=unknown exception", name);
    }
}

}  // namespace

struct RuntimeMonitor::Impl {
    explicit Impl(const RuntimeContext& runtime_context)
        : context(std::make_shared<MonitorContext>(MonitorContext{
              runtime_context.main_ctx, runtime_context.stats,
              runtime_context.workers, runtime_context.controller,
              runtime_context.dns_worker})) {
        loops = {
            std::make_shared<monitor_detail::MonitorLoop>(
                context->main_ctx.get_executor(), "sampling",
                [ctx = context] { return RuntimeSamplingLoop(*ctx); }, ReportMonitorExit),
            std::make_shared<monitor_detail::MonitorLoop>(
                context->main_ctx.get_executor(), "stats-output",
                [ctx = context] { return RuntimeStatsOutputLoop(*ctx); }, ReportMonitorExit),
        };
    }

    std::shared_ptr<MonitorContext> context;
    std::array<std::shared_ptr<monitor_detail::MonitorLoop>, 2> loops;
};

RuntimeMonitor::RuntimeMonitor(const RuntimeContext& ctx)
    : impl_(std::make_unique<Impl>(ctx)) {}

RuntimeMonitor::~RuntimeMonitor() = default;

void RuntimeMonitor::Start() {
    try {
        for (const auto& loop : impl_->loops) loop->Start();
    } catch (...) {
        RequestStop();
        throw;
    }
}

void RuntimeMonitor::RequestStop() noexcept {
    impl_->context->stopping = true;
    for (const auto& loop : impl_->loops) loop->RequestStop();
}

net::awaitable<void> RuntimeMonitor::AsyncJoin() {
    co_await net::this_coro::reset_cancellation_state(net::disable_cancellation());
    for (const auto& loop : impl_->loops) co_await loop->AsyncJoin();
}

