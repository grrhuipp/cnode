#include "acppnode/common.hpp"
#include "acppnode/infra/config.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/app/stats.hpp"
#include "acppnode/app/worker.hpp"
#include "acppnode/app/udp_session.hpp"
#include "acppnode/app/shared_user_store.hpp"
#include "acppnode/app/panel_sync.hpp"
#include "acppnode/geo/geodata.hpp"
#include "acppnode/dns/dns_service.hpp"
#include "acppnode/panel/v2board_panel.hpp"
#include "acppnode/protocol/inbound_registry.hpp"
#include "acppnode/protocol/vmess/vmess_protocol.hpp"

#ifdef USE_MIMALLOC
#include <mimalloc.h>
#endif

#include <boost/asio/signal_set.hpp>
#include <iostream>
#include <fstream>
#include <cstdio>
#include <thread>
#include <map>
#include <unordered_map>
#include <unordered_set>

#ifdef _WIN32
#include <windows.h>
#include <psapi.h>
#endif

using namespace acpp;

// ============================================================================
// 进程内存统计
// ============================================================================
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

void PrintUsage(const char* prog) {
    std::cout << "Usage: " << prog << " [options]\n"
              << "  -c, --config <file>   Config file (default: config.json)\n"
              << "  -t, --test            Test mode with built-in user\n"
              << "  -h, --help            Show help\n"
              << "  -v, --version         Show version\n";
}

void PrintVersion() {
#ifndef BUILD_ID
#define BUILD_ID "dev"
#endif
#ifndef BUILD_CHANNEL
#define BUILD_CHANNEL "release"
#endif
    std::cout << BUILD_CHANNEL << ":" << BUILD_ID << "\n";
}

static std::string FormatRate(double bytes_per_sec) {
    return acpp::FormatBytes(static_cast<uint64_t>(bytes_per_sec)) + "/s";
}

// ============================================================================
// 异步读取进程内存
// ============================================================================
static cobalt::task<double> GetMemoryMBAsync(net::any_io_executor /*exec*/) {
    ProcessMemory mem = ProcessMemory::Read();
    co_return static_cast<double>(mem.vm_rss) / (1024.0 * 1024.0);
}

// PanelSyncManager 已提取到 include/acppnode/app/panel_sync.hpp + src/app/panel_sync.cpp

// ============================================================================
// main
// ============================================================================
int main(int argc, char* argv[]) {
    std::string config_path = "config.json";
    bool test_mode = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-h" || arg == "--help")   { PrintUsage(argv[0]); return 0; }
        if (arg == "-v" || arg == "--version") { PrintVersion(); return 0; }
        if (arg == "-t" || arg == "--test")   { test_mode = true; }
        if ((arg == "-c" || arg == "--config") && i + 1 < argc) {
            config_path = argv[++i];
        }
    }

    auto config_opt = Config::LoadFromFile(config_path);
    if (!config_opt) {
        std::cerr << "Failed to load config from: " << config_path << "\n";
        return 1;
    }
    const Config& config = *config_opt;

    if (!Log::Init(config.GetLog().level,
                   config.GetLog().log_dir,
                   config.GetLog().max_days)) {
        std::cerr << "Failed to initialize logging\n";
        return 1;
    }

    LOG_CONSOLE("╔═══════════════════════════════════════════════════════════╗");
    LOG_CONSOLE("║              acppnode v1.0.0 - VMess Proxy                ║");
    LOG_CONSOLE("║       C++23 / Boost.Asio / SO_REUSEPORT / Lock-Free       ║");
    LOG_CONSOLE("╚═══════════════════════════════════════════════════════════╝");
    LOG_CONSOLE("");
    LOG_CONSOLE("Configuration:");
    LOG_CONSOLE("  Workers:        {}", config.GetWorkers());
    LOG_CONSOLE("  I/O backend:    epoll (Linux)");
    LOG_CONSOLE("  Accept model:   SO_REUSEPORT per-worker");
#ifdef USE_MIMALLOC
    LOG_CONSOLE("  Allocator:      mimalloc");
#else
    LOG_CONSOLE("  Allocator:      system");
#endif

    // ── GeoManager ──────────────────────────────────────────────────────────
    std::unique_ptr<geo::GeoManager> geo_manager;
    auto geoip_path   = config.GetConfigDir() / "geoip.dat";
    auto geosite_path = config.GetConfigDir() / "geosite.dat";

    if (std::filesystem::exists(geoip_path) || std::filesystem::exists(geosite_path)) {
        geo_manager = std::make_unique<geo::GeoManager>();
        if (geo_manager->Init(geoip_path, geosite_path)) {
            geo_manager->PreloadTags(config.GetUsedGeoIPTags(), config.GetUsedGeoSiteTags());
            auto gs = geo_manager->GetStats();
            LOG_CONSOLE("GeoData: {} geoip tags, {} geosite tags",
                        gs.geoip_tags_loaded, gs.geosite_tags_loaded);
        } else {
            LOG_WARN("Failed to initialize GeoManager");
            geo_manager.reset();
        }
    }

    // ── Stats + ConnectionLimiter ────────────────────────────────────────────
    auto stats = std::make_unique<ShardedStats>(config.GetWorkers());
    RateLimitConfig limiter_cfg;
    limiter_cfg.max_connections = config.GetLimits().max_connections;
    limiter_cfg.max_conn_per_ip = config.GetLimits().max_connections_per_ip;
    auto connection_limiter = std::make_shared<ConnectionLimiter>(limiter_cfg);

    // ── main_ctx（主线程：面板同步 + 统计 + 信号）────────────────────────────
    net::io_context main_ctx;

    // ── Workers（每个拥有独立 io_context）───────────────────────────────────
    std::vector<std::unique_ptr<net::io_context>> io_contexts;
    std::vector<net::executor_work_guard<net::io_context::executor_type>> work_guards;
    std::vector<std::unique_ptr<Worker>> workers;

    for (uint32_t i = 0; i < config.GetWorkers(); ++i) {
        io_contexts.push_back(std::make_unique<net::io_context>());
        work_guards.push_back(net::make_work_guard(*io_contexts[i]));
        workers.push_back(std::make_unique<Worker>(
            i, *io_contexts[i], config, *stats, geo_manager.get()));
    }

    // ── PanelSyncManager ────────────────────────────────────────────────────
    PanelSyncManager sync_manager(main_ctx, workers, connection_limiter);
    std::unique_ptr<IDnsService> panel_dns_service;

    if (!config.GetPanels().empty()) {
        DnsService::Config dns_config;
        dns_config.servers     = config.GetDns().servers;
        dns_config.timeout_sec = config.GetDns().timeout;
        dns_config.cache_size  = config.GetDns().cache_size;
        dns_config.min_ttl     = config.GetDns().min_ttl;
        dns_config.max_ttl     = config.GetDns().max_ttl;
        // 面板同步运行在 main_ctx，避免跨 io_context 复用 Worker 的 DNS 服务。
        panel_dns_service = CreateDnsService(main_ctx.get_executor(), dns_config);
    }

    if (!config.GetPanels().empty()) {
        LOG_CONSOLE("Panels:");
    }
    for (const auto& panel_config : config.GetPanels()) {
        V2BoardConfig v2cfg;
        v2cfg.name      = panel_config.name;
        v2cfg.api_host  = panel_config.api_host;
        v2cfg.api_key   = panel_config.api_key;
        v2cfg.node_type = panel_config.node_type;

        auto panel = CreateV2BoardPanel(main_ctx.get_executor(), v2cfg,
                                        panel_dns_service.get());
        sync_manager.AddPanel(std::move(panel), panel_config);

        std::string node_ids_str;
        for (size_t i = 0; i < panel_config.node_ids.size(); ++i) {
            if (i > 0) node_ids_str += ", ";
            node_ids_str += std::to_string(panel_config.node_ids[i]);
        }
        LOG_CONSOLE("  - {} [{}] ({}): nodes=[{}]",
                    panel_config.name, panel_config.node_type,
                    panel_config.api_host, node_ids_str);
    }

    // ── 静态入站（来自 inbound.json / config.json 的 Inbounds 配置）──────────
    std::vector<std::string> static_inbound_tags;
    auto& inbound_factory = InboundFactory::Instance();
    if (!config.GetInbounds().empty()) {
        LOG_CONSOLE("Static Inbounds:");
        for (const auto& inbound : config.GetInbounds()) {
            const std::string& protocol = inbound.protocol;
            // 主标签：使用配置的第一个 tag，或自动生成 {protocol}-{port}
            const std::string tag = inbound.tags.empty()
                ? std::format("{}-{}", protocol, inbound.port)
                : inbound.tags.front();
            // 所有标签（用于路由匹配）
            std::vector<std::string> all_tags = inbound.tags.empty()
                ? std::vector<std::string>{tag}
                : inbound.tags;

            if (!inbound_factory.Has(protocol)) {
                LOG_WARN("Static inbound '{}': unsupported protocol '{}', skipped", tag, protocol);
                continue;
            }

            InboundBuildRequest req;
            req.tag = tag;
            req.protocol = protocol;
            req.cipher_method = "aes-256-gcm";
            if (const auto* method = inbound.settings.if_contains("method");
                    method && method->is_string()) {
                req.cipher_method = std::string(method->as_string());
            }

            if (!inbound_factory.LoadStaticUsers(protocol, tag, inbound.settings)) {
                LOG_WARN("Static inbound '{}': load users failed, skipped", tag);
                continue;
            }

            bool register_failed = false;
            for (const auto& worker : workers) {
                InboundProtocolDeps deps;
                deps.vmess_user_manager  = &worker->GetUserManager();
                deps.trojan_user_manager = &worker->GetTrojanUserManager();
                deps.ss_user_manager     = &worker->GetSsUserManager();
                deps.stats               = &worker->Stats();

                inbound_factory.SyncWorkerUsers(protocol, deps, tag);
                auto handler = inbound_factory.CreateTcpHandler(
                    protocol, deps, connection_limiter, req);
                if (!handler) {
                    LOG_WARN("Static inbound '{}': create handler failed, skipped", tag);
                    register_failed = true;
                    break;
                }

                ListenerContext lc;
                lc.inbound_tag     = tag;
                lc.inbound_tags    = all_tags;
                lc.protocol        = protocol;
                lc.stream_settings = inbound.stream_settings;
                lc.sniff_config    = inbound.sniffing;
                lc.fixed_outbound  = inbound.outbound_tag.empty() ? "direct" : inbound.outbound_tag;
                lc.limiter         = connection_limiter;
                worker->RegisterListenerAsync(std::move(lc), std::move(handler));
            }

            if (register_failed) {
                for (const auto& worker : workers) {
                    worker->UnregisterListenerAsync(tag);
                }
                continue;
            }

            PortBinding binding;
            binding.port     = inbound.port;
            binding.protocol = protocol;
            binding.tag      = tag;
            binding.listen   = inbound.listen;
            for (const auto& worker : workers) {
                worker->AddListenerAsync(binding);
                InboundProtocolDeps deps;
                deps.vmess_user_manager  = &worker->GetUserManager();
                deps.trojan_user_manager = &worker->GetTrojanUserManager();
                deps.ss_user_manager     = &worker->GetSsUserManager();
                deps.stats               = &worker->Stats();

                auto udp_handler = inbound_factory.CreateUdpHandler(
                    protocol, deps, connection_limiter, req);
                if (udp_handler) {
                    worker->AddUdpListenerAsync(binding, std::move(udp_handler));
                }
            }
            static_inbound_tags.push_back(tag);
            LOG_CONSOLE("  - {} port={} protocol={} network={}",
                        tag, inbound.port, protocol, inbound.stream_settings.network);
        }
    }

    // ── 测试模式 ─────────────────────────────────────────────────────────────
    if (test_mode || (config.GetPanels().empty() && config.GetInbounds().empty())) {
        LOG_CONSOLE("");
        LOG_CONSOLE("Test mode: port=10086, UUID=b831381d-6324-4d53-ad4f-8cda48b30811");

        auto test_user = vmess::VMessUser::FromUUID(
            "b831381d-6324-4d53-ad4f-8cda48b30811", 1, "test@example.com");

        if (test_user) {
            constexpr const char* kTestTag = "test-vmess-10086";

            StreamSettings ss;
            ss.network  = "tcp";
            ss.security = "none";
            ss.RecomputeModes();

            SniffConfig sniff;
            sniff.enabled      = true;
            sniff.dest_override = {"tls", "http"};

            std::vector<vmess::VMessUser> users = {*test_user};
            vmess::VMessUserManager::UpdateSharedUsersForTag(kTestTag, std::move(users));

            InboundBuildRequest req;
            req.tag = kTestTag;
            req.protocol = "vmess";

            for (const auto& worker : workers) {
                InboundProtocolDeps deps;
                deps.vmess_user_manager  = &worker->GetUserManager();
                deps.trojan_user_manager = &worker->GetTrojanUserManager();
                deps.ss_user_manager     = &worker->GetSsUserManager();
                deps.stats               = &worker->Stats();

                inbound_factory.SyncWorkerUsers("vmess", deps, kTestTag);
                auto handler = inbound_factory.CreateTcpHandler(
                    "vmess", deps, connection_limiter, req);
                if (!handler) {
                    LOG_WARN("Test mode: failed to create vmess inbound handler on worker {}", worker->Id());
                    continue;
                }

                ListenerContext lc;
                lc.inbound_tag    = kTestTag;
                lc.inbound_tags   = {kTestTag};
                lc.protocol       = "vmess";
                lc.stream_settings = ss;
                lc.sniff_config   = sniff;
                lc.limiter        = connection_limiter;

                // RegisterListenerAsync：post 到 Worker 线程，在 run() 启动后执行
                worker->RegisterListenerAsync(std::move(lc), std::move(handler));
            }

            PortBinding test_binding;
            test_binding.port     = 10086;
            test_binding.protocol = "vmess";
            test_binding.tag      = kTestTag;
            test_binding.listen   = "0.0.0.0";

            for (const auto& worker : workers) {
                // AddListenerAsync：post 到 Worker 线程，在 run() 启动后 SO_REUSEPORT bind
                worker->AddListenerAsync(test_binding);
            }
        }
    }

    // ── 启动工作线程（run() 开始后，之前 post 的注册/监听任务依次执行）────────
    std::vector<std::thread> worker_threads;
    for (uint32_t i = 0; i < workers.size(); ++i) {
        worker_threads.emplace_back([&io_contexts, i]() {
            io_contexts[i]->run();
        });
    }

    LOG_CONSOLE("");
    LOG_CONSOLE("Server started with {} workers (SO_REUSEPORT)", workers.size());
    LOG_CONSOLE("Press Ctrl+C to stop");

    // ── 面板同步启动 ─────────────────────────────────────────────────────────
    if (!config.GetPanels().empty()) {
        sync_manager.Start();
    }

    // ── 信号处理 ─────────────────────────────────────────────────────────────
    net::signal_set signals(main_ctx, SIGINT, SIGTERM);
    std::atomic<bool> running{true};

    signals.async_wait([&running, &sync_manager, &workers, &static_inbound_tags,
                        &work_guards, &io_contexts, &main_ctx](
                           const boost::system::error_code&, int signo) {
        LOG_CONSOLE("Received signal {}, shutting down...", signo);
        running = false;

        sync_manager.Stop();

        // 停止所有 Worker 的监听（post 到各 Worker 线程）
        for (const auto& tag : sync_manager.RegisteredTags()) {
            for (const auto& worker : workers) {
                worker->RemoveListenerAsync(tag);
            }
        }
        for (const auto& tag : static_inbound_tags) {
            for (const auto& worker : workers) {
                worker->RemoveListenerAsync(tag);
            }
        }

        // 释放 work_guard，Worker io_context 在处理完队列后自然退出
        work_guards.clear();
        for (const auto& ctx : io_contexts) {
            ctx->stop();
        }

        // 停止主线程 io_context：让 sample_coro / stats_coro / SyncLoop
        // 的 timer 不再等待，main_ctx.run() 立即返回
        main_ctx.stop();
    });

    // ── 统计采样协程（每秒，主线程）─────────────────────────────────────────
    uint32_t last_sample_total_conns = 0;
#ifdef USE_MIMALLOC
    auto last_force_collect_at = steady_clock::time_point{};
#endif
    auto sample_coro = [&running, &stats, &workers, &last_sample_total_conns
#ifdef USE_MIMALLOC
        , &last_force_collect_at
#endif
        ](net::steady_timer& timer) -> cobalt::task<void> {
        while (running) {
            stats->SampleNow();
#ifdef USE_MIMALLOC
            constexpr uint32_t kForceCollectMinPrevConns = 4096;
            constexpr uint32_t kForceCollectDropFactor = 8;
            constexpr uint32_t kForceCollectConnFloor = 64;
            constexpr auto kForceCollectCooldown = std::chrono::seconds(3);

            uint32_t total_conns = 0;
            for (const auto& w : workers) {
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

            if ((burst_drain || newly_idle) && cooldown_ok) {
                mi_collect(true);
                last_force_collect_at = now;
            }

            last_sample_total_conns = total_conns;
#endif
            timer.expires_after(std::chrono::seconds(1));
            auto [ec] = co_await timer.async_wait(net::as_tuple(cobalt::use_op));
            if (ec) break;
        }
    };
    net::steady_timer sample_timer(main_ctx);
    cobalt::spawn(main_ctx.get_executor(), sample_coro(sample_timer), net::detached);

    // ── 统计输出协程（每 N 秒，主线程）──────────────────────────────────────
    auto stats_coro = [&running, &stats, &workers, &main_ctx, &sync_manager](net::steady_timer& timer) -> cobalt::task<void> {
        while (running) {
            auto snapshot = stats->AggregateWithRate();

            DnsCacheStats dns_stats;
            if (!workers.empty() && workers[0]->GetDnsService()) {
                dns_stats = workers[0]->GetDnsService()->GetCacheStats();
            }

            double dns_hit_rate = 0.0;
            uint64_t dns_total = dns_stats.hits + dns_stats.misses;
            if (dns_total > 0) {
                dns_hit_rate = 100.0 * static_cast<double>(dns_stats.hits)
                                     / static_cast<double>(dns_total);
            }

            // 汇总各 Worker 活跃连接数
            uint32_t total_conns = 0;
            for (const auto& w : workers) {
                total_conns += w->GetActiveConnectionCount();
            }

#ifdef USE_MIMALLOC
            // 常态只做轻量 collect；快速强制回收由每秒 sample_coro 负责。
            mi_collect(false);
#endif

            double mem_mb = co_await GetMemoryMBAsync(main_ctx.get_executor());

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
                for (const auto& worker : workers) {
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

            auto node_stats = sync_manager.GetNodeStats();
            if (!node_stats.empty()) {
                LOG_INFO("┌────────────┬───────┬─────────┬────────┬────────┬──────────┬──────────┐");
                LOG_INFO("│ Node       │ Port  │ Network │ Users  │ Online │ ↑ Up     │ ↓ Down   │");
                LOG_INFO("├────────────┼───────┼─────────┼────────┼────────┼──────────┼──────────┤");
                for (const auto& ns : node_stats) {
                    std::string name = std::format("{}-{}", ns.panel_name, ns.node_id);
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
    net::steady_timer stats_timer(main_ctx);
    cobalt::spawn(main_ctx.get_executor(), stats_coro(stats_timer), net::detached);

    // ── 主线程阻塞（运行 main_ctx：信号 + 面板同步 + 统计）────────────────────
    main_ctx.run();

    // 等待 Worker 线程结束
    for (auto& t : worker_threads) {
        if (t.joinable()) t.join();
    }

    // 让 main_ctx 中的 detached 协程完成退出，避免析构时 use-after-free
    main_ctx.restart();
    main_ctx.run_for(std::chrono::milliseconds(100));

    LOG_CONSOLE("=== acppnode stopped ===");
    Log::Shutdown();
    return 0;
}
