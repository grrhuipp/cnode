#include "acppnode/app/bootstrap_monitor.hpp"
#include "acppnode/app/bootstrap_runtime.hpp"
#include "../common/awaitable_task_group.hpp"
#include "../common/process_resources.hpp"
#include "acppnode/common/defaults.hpp"
#include "acppnode/common/memory_stats.hpp"
#include "acppnode/runtime/channel.hpp"
#include "acppnode/service/controller/controller.hpp"
#include "acppnode/core/naming.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/app/proxyman/inbound/user_store.hpp"
#include "acppnode/app/dns/dns_service.hpp"
#include "acppnode/app/stats.hpp"
#include "acppnode/runtime/runtime.hpp"
#include "acppnode/runtime/runtime_stats.hpp"

#include <asio/as_tuple.hpp>
#include <asio/steady_timer.hpp>
#include <chrono>
#include <exception>
#include <fstream>

#ifdef __GLIBC__
#include <malloc.h>
#endif
#ifdef _WIN32
#include <windows.h>
#include <psapi.h>
#endif

namespace acpp {
namespace {
struct MonitorContext {
    net::any_io_executor executor;
    StatsSampler& stats_sampler;
    Runtime& runtime;
    Controller& controller;
    app::dns::DNSService& dns_service;
};

size_t ReadResidentMemoryBytes() {
#ifdef _WIN32
    PROCESS_MEMORY_COUNTERS_EX counters{};
    if (GetProcessMemoryInfo(GetCurrentProcess(),
            reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&counters), sizeof(counters)))
        return static_cast<size_t>(counters.WorkingSetSize);
#else
    std::ifstream status("/proc/self/status");
    std::string line;
    while (std::getline(status, line))
        if (line.starts_with("VmRSS:")) return std::stoull(line.substr(6)) * 1024;
#endif
    return 0;
}

std::string FormatRate(double bytes_per_sec) {
    return FormatBytes(static_cast<uint64_t>(bytes_per_sec)) + "/s";
}

net::awaitable<void> RuntimeSamplingLoop(const MonitorContext& ctx) {
    net::steady_timer timer(ctx.executor);
    auto last_log_flush = std::chrono::steady_clock::time_point{};
    while (true) {
        const auto snapshot = co_await ctx.runtime.CollectRuntimeStats(false);
        ctx.stats_sampler.SampleNow(snapshot.stats);
        const auto now = std::chrono::steady_clock::now();
        if (last_log_flush.time_since_epoch().count() == 0 || now - last_log_flush >= std::chrono::seconds(5)) {
            Log::Flush();
            last_log_flush = now;
        }
        timer.expires_after(std::chrono::seconds(1));
        auto [error] = co_await timer.async_wait(net::as_tuple(net::use_awaitable));
        if (error) co_return;
    }
}

net::awaitable<void> RuntimeStatsOutputLoop(const MonitorContext& ctx) {
    net::steady_timer timer(ctx.executor);
#ifdef __GLIBC__
    auto last_glibc_sample = std::chrono::steady_clock::time_point{};
#endif
    while (true) {
        const auto runtime = co_await ctx.runtime.CollectRuntimeStats(true);
        const auto stats = ctx.stats_sampler.WithCurrentRate(runtime.stats);
        const auto dns = co_await ctx.dns_service.GetCacheStats();
        const auto dns_total = dns.hits + dns.misses;
        const auto hit_rate = dns_total ? 100.0 * static_cast<double>(dns.hits) / dns_total : 0.0;
        const auto users = proxyman::inbound::UserStore::GetStats();
        LOG_INFO("runtime conn={} mem={:.1f}MB traffic_in={} traffic_out={} rate_down={} rate_up={} dns_hit={:.0f}% dns_cache={}/{} udp_sockets={} users={}",
            runtime.active_connections, static_cast<double>(ReadResidentMemoryBytes()) / (1024 * 1024),
            FormatBytes(stats.bytes_in), FormatBytes(stats.bytes_out),
            FormatRate(stats.bytes_in_rate), FormatRate(stats.bytes_out_rate), hit_rate,
            dns.entries, dns.capacity, runtime.memory.udp_sockets, users.TotalUsers());
        const auto descriptors = ReadProcessDescriptors();
        LOG_INFO("runtime.process {}={} soft_limit={}", descriptors.kind,
            descriptors.open ? std::to_string(*descriptors.open) : "unknown",
            descriptors.soft_limit ? std::to_string(*descriptors.soft_limit)
                : descriptors.soft_limit_unlimited ? "unlimited" : "unknown");
        if (runtime.resources) {
            const auto& r = *runtime.resources;
            LOG_INFO("runtime.resources conn={} udp_sockets={} udp_listeners={} udp_receive_loops={} udp_resource_drops={} udp_associations={} udp_retiring={} udp_input_packets={} udp_input_bytes={} udp_reply_packets={} udp_reply_bytes={} udp_reply_senders={} udp_native_dispatches={} timeout_events={} timeout_heap={}/{} timeout_buckets={} timeout_ready={} timeout_waiters={}",
                runtime.active_connections, runtime.memory.udp_sockets,
                r.udp_listeners, r.udp_receive_loops, r.udp_resource_drops,
                r.udp_associations, r.udp_retiring_associations, r.udp_input_datagrams,
                r.udp_input_bytes, r.udp_reply_datagrams, r.udp_reply_bytes,
                r.udp_reply_senders, r.udp_native_dispatches, r.timeout_events,
                r.timeout_heap_entries, r.timeout_heap_capacity, r.timeout_event_buckets,
                r.timeout_ready_events, r.timeout_waiters);
        }
#ifdef __GLIBC__
        const auto now = std::chrono::steady_clock::now();
        if (last_glibc_sample.time_since_epoch().count() == 0 || now - last_glibc_sample >= std::chrono::minutes(5)) {
            const auto heap = ::mallinfo2();
            LOG_INFO("runtime.glibc arena={}MB used={}MB free={}MB mmap={}MB mmap_chunks={} top_free={}MB",
                heap.arena / (1024 * 1024), heap.uordblks / (1024 * 1024),
                heap.fordblks / (1024 * 1024), heap.hblkhd / (1024 * 1024),
                heap.hblks, heap.keepcost / (1024 * 1024));
            last_glibc_sample = now;
        }
#endif
#ifdef CNODE_MEMORY_STATS
        const auto allocation_stats = memory::SnapshotRuntimeMemoryStats();
        LOG_DEBUG("runtime.memory async_stream={}/{} tcp_stream={}/{} tls_stream={}/{}",
            allocation_stats.async_streams_live, allocation_stats.async_streams_peak,
            allocation_stats.tcp_streams_live, allocation_stats.tcp_streams_peak,
            allocation_stats.tls_streams_live, allocation_stats.tls_streams_peak);
#endif
        const auto nodes = co_await ctx.controller.GetNodeStats();
        size_t total_users = 0;
        size_t online_users = 0;
        uint64_t upload = 0;
        uint64_t download = 0;
        for (const auto& node : nodes) {
            total_users += node.total_users;
            online_users += node.online_users;
            upload += node.bytes_up;
            download += node.bytes_down;
            LOG_DEBUG("runtime.node name={} port={} network={} users={} online={} upload={} download={}",
                naming::BuildPanelNodeStatsKey(node.panel_name, node.node_id), node.port,
                node.network, node.total_users, node.online_users,
                FormatBytes(node.bytes_up), FormatBytes(node.bytes_down));
        }
        if (!nodes.empty()) LOG_INFO("runtime.nodes count={} users={} online={} upload={} download={}",
            nodes.size(), total_users, online_users, FormatBytes(upload), FormatBytes(download));
        timer.expires_after(std::chrono::seconds(defaults::kStatsOutputInterval));
        auto [error] = co_await timer.async_wait(net::as_tuple(net::use_awaitable));
        if (error) co_return;
    }
}

void ReportMonitorExit(std::string_view name, std::exception_ptr failure) {
    if (!failure) { LOG_DEBUG("runtime monitor loop={} stopped", name); return; }
    try { std::rethrow_exception(failure); }
    catch (const IoSystemError& error) {
        if (error.code() == io_error::operation_aborted) LOG_DEBUG("runtime monitor loop={} stopped", name);
        else LOG_ERROR("runtime monitor loop={} failed: {}", name, error.what());
    } catch (const std::exception& error) { LOG_ERROR("runtime monitor loop={} failed: {}", name, error.what()); }
    catch (...) { LOG_ERROR("runtime monitor loop={} failed with unknown exception", name); }
}
}

struct RuntimeMonitor::Impl {
    explicit Impl(const RuntimeContext& runtime)
        : context{runtime.monitor_executor, runtime.stats_sampler, runtime.runtime,
                  runtime.controller, runtime.dns_service},
          channel(context.executor, 4) {}
    net::awaitable<void> Run() {
        if (stopping) co_return;
        if (running) throw std::logic_error("runtime monitor is already running");
        running = true;
        struct Reset { Impl& owner; ~Reset() { owner.tasks = nullptr; owner.running = false; } } reset{*this};
        co_await RunAwaitableTaskGroup(context.executor, [this](AwaitableTaskGroup& group) {
            tasks = &group;
            group.Spawn(RunLoop(true));
            group.Spawn(RunLoop(false));
        });
    }
    net::awaitable<void> RunLoop(bool sampling) {
        std::exception_ptr failure;
        try {
            if (sampling) co_await RuntimeSamplingLoop(context);
            else co_await RuntimeStatsOutputLoop(context);
        } catch (...) { failure = std::current_exception(); }
        ReportMonitorExit(sampling ? "sampling" : "stats-output", failure);
    }
    void Stop() { stopping = true; if (tasks) tasks->Cancel(); }
    MonitorContext context;
    ServiceChannel channel;
    AwaitableTaskGroup* tasks = nullptr;
    bool running = false;
    bool stopping = false;
};

RuntimeMonitor::RuntimeMonitor(const RuntimeContext& context)
    : impl_(std::make_shared<Impl>(context)), stop_ticket_(impl_->channel.TryReserve()) {
    if (!stop_ticket_) throw ServiceChannelFull();
}
RuntimeMonitor::~RuntimeMonitor() = default;
net::awaitable<void> RuntimeMonitor::Run() {
    auto owner = impl_;
    co_await owner->channel.Post(owner->Run());
}
bool RuntimeMonitor::RequestStop() {
    return impl_->channel.SendReserved(std::move(stop_ticket_), [owner = impl_] { owner->Stop(); });
}
}  // namespace acpp
