#include "app/bootstrap.hpp"
#include "app/worker_batch.hpp"
#include "common/monitor_loop.hpp"
#include "app/process_descriptors.hpp"
#include "api/api.hpp"
#include "app/dns.hpp"
#include "app/prepared_inbound.hpp"
#include "app/user_store.hpp"
#include "app/group_coordinator.hpp"
#include "app/stats.hpp"
#include "app/worker.hpp"
#include "app/router.hpp"
#include "common/allocator.hpp"
#include "common/asio_types.hpp"
#include "common/defaults.hpp"
#include "common/constants.hpp"
#include "geo/geodata.hpp"
#include "infra/config.hpp"
#include "infra/log.hpp"
#include "common/error.hpp"
#include "app/outbound_handler.hpp"
#include "controller/controller.hpp"
#include "transport/timeout_scheduler.hpp"
#include "transport/tls_stream.hpp"
#include <asio/co_spawn.hpp>
#include <asio/executor_work_guard.hpp>
#include <asio/post.hpp>
#include <asio/redirect_error.hpp>
#include <asio/signal_set.hpp>
#include <asio/steady_timer.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <charconv>
#include <chrono>
#include <cmath>
#include <cerrno>
#include <csignal>
#include <cstdlib>
#include <exception>
#include <filesystem>
#include <format>
#include <fstream>
#include <iostream>
#include <limits>
#include <memory>
#include <optional>
#include <ostream>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

#include <dirent.h>
#include <sys/resource.h>

#ifndef BUILD_CHANNEL
#define BUILD_CHANNEL "release"
#endif

#ifndef BUILD_ID
#define BUILD_ID "dev"
#endif

namespace app {

ProcessDescriptors ReadProcessDescriptors() noexcept {
    ProcessDescriptors result;
    rlimit limits{};
    if (::getrlimit(RLIMIT_NOFILE, &limits) == 0) {
        result.soft_limit_unlimited = limits.rlim_cur == RLIM_INFINITY;
        if (!result.soft_limit_unlimited) {
            result.soft_limit = static_cast<size_t>(limits.rlim_cur);
        }
    }
    if (DIR* directory = ::opendir("/proc/self/fd")) {
        size_t count = 0;
        errno = 0;
        while (const auto* entry = ::readdir(directory)) {
            if (entry->d_name[0] >= '0' && entry->d_name[0] <= '9') ++count;
        }
        const bool complete = errno == 0;
        ::closedir(directory);
        if (complete && count > 0) result.open = count - 1;
    }
    return result;
}

namespace {

enum class CommandLineAction {
    None,
    Help,
    Version,
    Error,
};

enum class ConfigPathMode {
    Auto,
    File,
    Directory,
};

struct CommandLineOptions {
    std::string config_path = std::string(common::kDefaultConfigFile);
    ConfigPathMode config_mode = ConfigPathMode::Auto;
    bool test_mode = false;
    CommandLineAction action = CommandLineAction::None;
    std::string error;
};

bool SetError(CommandLineOptions& options, std::string error) {
    options.action = CommandLineAction::Error;
    options.error = std::move(error);
    return false;
}

bool ReadValue(
    CommandLineOptions& options,
    std::string_view option,
    int argc,
    char* argv[],
    int& index) {
    if (index + 1 >= argc) {
        return SetError(options, std::format("Option {} requires a value", option));
    }

    options.config_path = argv[++index];
    return true;
}

[[nodiscard]] CommandLineOptions ParseCommandLine(int argc, char* argv[]) {
    CommandLineOptions options;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-h" || arg == "--help") {
            if (options.action == CommandLineAction::None) {
                options.action = CommandLineAction::Help;
            }
            continue;
        }
        if (arg == "-v" || arg == "--version") {
            if (options.action == CommandLineAction::None) {
                options.action = CommandLineAction::Version;
            }
            continue;
        }
        if (arg == "-t" || arg == "--test") {
            options.test_mode = true;
            continue;
        }
        if (arg == "-c" || arg == "--config") {
            if (!ReadValue(options, arg, argc, argv, i)) break;
            options.config_mode = ConfigPathMode::Auto;
            continue;
        }
        if (arg == "--config-file") {
            if (!ReadValue(options, arg, argc, argv, i)) break;
            options.config_mode = ConfigPathMode::File;
            continue;
        }
        if (arg == "-C" || arg == "--config-dir") {
            if (!ReadValue(options, arg, argc, argv, i)) break;
            options.config_mode = ConfigPathMode::Directory;
            continue;
        }
        if (!arg.empty() && arg.front() == '-') {
            SetError(options, std::format("Unknown option: {}", arg));
            break;
        }
        SetError(options, std::format("Unexpected argument: {}", arg));
        break;
    }

    return options;
}

void PrintUsage(std::ostream& out, std::string_view prog) {
    out << "Usage: " << prog << " [options]\n"
        << "  -c, --config <path>       Config file or directory (default: "
        << common::kDefaultConfigFile << ")\n"
        << "      --config-file <file>  Load one config file; sidecars use its directory\n"
        << "  -C, --config-dir <dir>    Load config.json and sidecars from directory\n"
        << "  -t, --test                Test mode with built-in user\n"
        << "  -h, --help                Show help\n"
        << "  -v, --version             Show version\n"
        << "\n"
        << "Directory mode reads: "
        << common::kDefaultConfigFile << ", "
        << common::kInboundFile << ", "
        << common::kOutboundFile << ", "
        << common::kRouteFile << "\n";
}

void PrintVersion(std::ostream& out) {
    out << BUILD_CHANNEL << ":" << BUILD_ID << "\n";
}

std::optional<infra::Config> LoadConfigFromCli(
    const CommandLineOptions& cli,
    bool& error_reported) {
    const std::filesystem::path config_path(cli.config_path);

    if (cli.config_mode == ConfigPathMode::Directory) {
        std::error_code ec;
        if (!std::filesystem::is_directory(config_path, ec)) {
            infra::Log::WriteConsole(infra::LogLevel::ERROR, std::format(
                "--config-dir expects an existing directory: {}", cli.config_path));
            error_reported = true;
            return std::nullopt;
        }
    }

    if (cli.config_mode == ConfigPathMode::File) {
        std::error_code ec;
        if (std::filesystem::is_directory(config_path, ec)) {
            infra::Log::WriteConsole(infra::LogLevel::ERROR, std::format(
                "--config-file expects a file, got directory: {}", cli.config_path));
            error_reported = true;
            return std::nullopt;
        }
    }

    return infra::LoadConfig(config_path);
}

constexpr std::string_view IoBackendName() noexcept {
#if defined(CNODE_IO_URING_ENABLED)
    return "io_uring";
#else
    return "epoll";
#endif
}


struct WorkerPool {
    // Cold construction failure unwinds in reverse declaration order:
    // work guards release first, then Workers destroy every socket/service
    // while its io_context is still alive; io_contexts are destroyed last.
    // Runtime releases live state and each io_context on its data thread.
    std::vector<std::unique_ptr<net::io_context>> io_contexts;
    std::vector<std::unique_ptr<Worker>> workers;
    std::vector<net::executor_work_guard<net::io_context::executor_type>> work_guards;
};

struct BootstrapEnvironment {
    std::unique_ptr<net::io_context> main_ctx;
    std::unique_ptr<app::DNSWorker> dns_worker;
    std::unique_ptr<app::DNS> panel_dns_service;
    std::unique_ptr<geo::GeoDatabase> geo_database;
    std::unique_ptr<ShardedStats> stats;
    WorkerPool worker_pool;
    std::unique_ptr<controller::Controller> controller;
    std::vector<PreparedInbound> inbound_startup;
    bool enable_controller = false;
};

::app::DnsConfig MakeDnsServiceConfig(const infra::Config& config) {
    ::app::DnsConfig dns_config;
    dns_config.servers     = config.dns.servers;
    dns_config.timeout_sec = config.dns.timeout;
    dns_config.cache_size  = config.dns.cache_size;
    dns_config.min_ttl     = config.dns.min_ttl;
    dns_config.max_ttl     = config.dns.max_ttl;
    return dns_config;
}

// 只有路由实际引用 geo 分类时才加载数据；未引用时 Router 不需要 GeoDatabase。
std::unique_ptr<geo::GeoDatabase> LoadGeoDatabase(const infra::Config& config) {
    const auto geoip_tags = infra::GetUsedGeoIPTags(config.routing);
    const auto geosite_tags = infra::GetUsedGeoSiteTags(config.routing);
    if (geoip_tags.empty() && geosite_tags.empty()) {
        return nullptr;
    }

    const auto geoip_path   = config.config_dir / common::kGeoIpFile;
    const auto geosite_path = config.config_dir / common::kGeoSiteFile;
    if (!geoip_tags.empty() && !std::filesystem::exists(geoip_path)) {
        throw std::runtime_error(std::format(
            "routing geoip tags require '{}'", geoip_path.string()));
    }
    if (!geosite_tags.empty() && !std::filesystem::exists(geosite_path)) {
        throw std::runtime_error(std::format(
            "routing geosite tags require '{}'", geosite_path.string()));
    }

    auto geo_database = std::make_unique<geo::GeoDatabase>(
        geoip_path, geoip_tags, geosite_path, geosite_tags);
    const auto gs = geo_database->GetStats();
    LOG_CONSOLE("Geodata ready: geoip_tags={} geosite_tags={}",
                gs.geoip_tags_loaded, gs.geosite_tags_loaded);
    return geo_database;
}

uint32_t ComputePressureThreshold(const WorkerRuntimeConfig& config) {
    const uint32_t configured_max = config.limits.max_connections;
    const uint32_t workers = std::max<uint32_t>(1, config.workers);
    const uint64_t scaled_default = std::min<uint64_t>(
        static_cast<uint64_t>(common::kMaxConnectionsPerWorker) * workers,
        std::numeric_limits<uint32_t>::max());
    uint32_t effective_max = static_cast<uint32_t>(scaled_default);
    if (configured_max > 0) {
        effective_max = std::min(effective_max, configured_max);
    }
    if (effective_max == 0) {
        return 0;
    }
    const uint32_t per_worker_max = effective_max / workers;
    return std::max<uint32_t>(
        1, static_cast<uint32_t>(
               static_cast<uint64_t>(per_worker_max) * common::kPressurePercent / 100));
}

uint32_t ComputePressureIdleTimeout(const WorkerRuntimeConfig& config) {
    return config.timeouts.idle > common::kPressureIdleTimeout
        ? common::kPressureIdleTimeout
        : 0;
}

std::vector<PreparedOutboundConfig> PrepareStartupOutbounds(
    std::span<const infra::OutboundSourceConfig> sources) {
    std::vector<PreparedOutboundConfig> prepared;
    prepared.reserve(sources.size());
    for (const auto& raw_config : sources) {
        auto item = PrepareOutboundConfig(raw_config);
        if (!item) {
            throw std::invalid_argument(
                "outbound '" + raw_config.tag + "' protocol '" +
                raw_config.protocol + "' is unsupported or invalid");
        }
        prepared.push_back(std::move(*item));
    }
    return prepared;
}

WorkerRuntimeConfig MakeWorkerRuntimeConfig(
    const infra::Config& config,
    infra::RoutingConfig routing,
    std::vector<PreparedOutboundConfig> outbounds,
    geo::GeoDatabase* geo_database) {
    WorkerRuntimeConfig runtime_config;
    runtime_config.timeouts = config.timeouts;
    runtime_config.limits = config.limits;
    runtime_config.router = std::make_shared<const app::Router>(
        routing, geo_database);
    runtime_config.outbounds = std::move(outbounds);
    runtime_config.workers = config.workers;
    runtime_config.pressure_threshold = ComputePressureThreshold(runtime_config);
    runtime_config.pressure_idle_timeout = ComputePressureIdleTimeout(runtime_config);
    return runtime_config;
}

void SetupPanels(net::io_context& main_ctx,
                 controller::Controller& controller,
                 const infra::Config& config,
                 app::DNS& panel_dns_service) {
    if (config.panels.empty()) {
        return;
    }

    for (const auto& panel_config : config.panels) {
        for (int node_id : panel_config.NodeIDs.Values()) {

            infra::PanelConfig node_panel_config = panel_config;
            node_panel_config.NodeIDs = infra::PanelNodeIds::Single(node_id);

            auto panel = api::CreatePanelClient(main_ctx, {
                .Name = panel_config.Name,
                .APIHost = panel_config.APIHost,
                .Key = panel_config.Key,
                .RequestTimeout = panel_config.RequestTimeout,
                .NodeID = node_id,
                .NodeType = panel_config.NodeType,
            }, panel_dns_service);
            controller.AddPanel(std::move(panel), node_panel_config);
            const infra::PanelLogContext log_context{panel_config.Name, panel_config.APIHost,
                node_id, panel_config.NodeType};
            LOG_PANEL_INFO(log_context, "Panel node configured");
        }
    }
}

[[nodiscard]] WorkerPool CreateWorkerPool(
    const WorkerRuntimeConfig& runtime_config,
    ShardedStats& stats,
    geo::GeoDatabase* geo_database,
    app::DNSWorker& dns_worker,
    net::io_context& control_io) {
    WorkerPool pool;
    const uint32_t workers = std::max<uint32_t>(1, runtime_config.workers);
    pool.workers.reserve(workers);
    pool.io_contexts.reserve(workers);
    pool.work_guards.reserve(workers);
    auto coordinator = std::make_shared<GroupCoordinator>(control_io);

    // 每个 Worker context 只由其数据线程运行（RunDataThread/RunEventLoop）。
    // hint 1 让本线程发起的 post 进入线程私有队列；它仍是加锁调度器与反应器，
    // 控制面与其他 Worker 的跨线程投递继续走加锁路径。
    for (uint32_t i = 0; i < workers; ++i) {
        pool.io_contexts.push_back(std::make_unique<net::io_context>(ASIO_CONCURRENCY_HINT_1));
        pool.work_guards.push_back(net::make_work_guard(*pool.io_contexts[i]));
        auto& worker_stats = stats.GetShard(i);
        pool.workers.push_back(std::make_unique<Worker>(
            i, *pool.io_contexts[i], runtime_config, worker_stats, dns_worker,
            coordinator, geo_database));
    }

    return pool;
}

// Takes the loaded configuration by value: every runtime owner copies or moves
// what it keeps, so the source is released once startup preparation returns.
[[nodiscard]] BootstrapEnvironment CreateBootstrapEnvironment(
    infra::Config config,
    bool test_mode) {
    transport::TlsStream::InitializeIo();
    BootstrapEnvironment env;
    const bool enable_test_mode =
        test_mode || (config.panels.empty() && config.static_inbounds.empty());
    auto outbounds = PrepareStartupOutbounds(config.outbounds);
    auto inbounds = PrepareStartupInbounds(std::move(config.static_inbounds), enable_test_mode);
    constexpr int kMainIoConcurrencyHint =
        static_cast<int>(ASIO_CONCURRENCY_HINT_ID | ASIO_CONCURRENCY_HINT_LOCKING_SCHEDULER);
    env.main_ctx = std::make_unique<net::io_context>(kMainIoConcurrencyHint);
    env.dns_worker = std::make_unique<app::DNSWorker>(
        *env.main_ctx, MakeDnsServiceConfig(config), common::kWorkerMailboxCapacity);
    env.panel_dns_service = std::make_unique<app::DNS>(*env.dns_worker);
    // Geo tags are read from the routing rules before they move to the Workers.
    env.geo_database = LoadGeoDatabase(config);
    env.stats = std::make_unique<ShardedStats>(config.workers);
    const WorkerRuntimeConfig worker_runtime_config =
        MakeWorkerRuntimeConfig(config, std::move(config.routing), std::move(outbounds),
                                env.geo_database.get());
    // Every source and protocol payload is prepared before one RCU publication
    // through the core shared with panel nodes. Workers do not exist yet: each
    // captures the committed snapshot when it is constructed below. These
    // borrowed references stay in this call.
    std::vector<UserStore::UserUpdate> user_updates;
    user_updates.reserve(inbounds.size());
    for (const auto& inbound : inbounds) {
        user_updates.push_back({inbound.binding.tag, *inbound.users});
    }
    std::optional<PreparedUserPublication> user_publication;
    if (!user_updates.empty()) {
        user_publication = PrepareUserPublication(
            UserStore::PrepareUsers(user_updates), 0);
        user_publication->Commit();
    }
    for (auto& inbound : inbounds) {
        inbound.users.reset();
    }
    try {
        env.worker_pool = CreateWorkerPool(
            worker_runtime_config, *env.stats, env.geo_database.get(), *env.dns_worker,
            *env.main_ctx);
        env.controller = std::make_unique<controller::Controller>(
            *env.main_ctx, env.worker_pool.workers);

        SetupPanels(*env.main_ctx, *env.controller, config, *env.panel_dns_service);
        if (enable_test_mode) {
            LOG_CONSOLE("Test mode enabled: port={}", common::kTestPort);
        }
        env.inbound_startup = std::move(inbounds);
        env.enable_controller = !config.panels.empty();
        return env;
    } catch (...) {
        if (user_publication) {
            UserStore::CommitSnapshot(
                std::move(user_publication->rollback.previous));
        }
        throw;
    }
}

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
        return ::app::FormatBytes(0) + "/s";
    }
    constexpr double kMaxBytes =
        static_cast<double>(std::numeric_limits<uint64_t>::max());
    const uint64_t rate = bytes_per_sec >= kMaxBytes
        ? std::numeric_limits<uint64_t>::max()
        : static_cast<uint64_t>(bytes_per_sec);
    return ::app::FormatBytes(rate) + "/s";
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

net::awaitable<void> StartWorkerInbounds(
    Worker& worker,
    std::span<const PreparedInbound> inbounds) {
    worker.StartRuntime();

    for (const auto& inbound : inbounds) {
        const auto failure = co_await InstallInbound(worker, inbound);
        if (failure != InboundInstallFailure::None) {
            throw std::runtime_error(std::format(
                "static inbound startup failed worker={} tag={} port={} stage={}",
                worker.Id(), inbound.binding.tag, inbound.binding.port,
                InboundInstallFailureName(failure)));
        }
    }
}

template <typename StopFn>
[[nodiscard]] std::unique_ptr<net::signal_set> InstallShutdownHandler(
    net::io_context& io_context, StopFn request_stop) {
    auto signals = std::make_unique<net::signal_set>(io_context);
    signals->add(SIGINT);
    signals->add(SIGTERM);

    signals->async_wait([request_stop = std::move(request_stop)](const IoErrorCode& ec, int signo) {
        if (ec) return;
        LOG_CONSOLE("Shutdown requested: signal={}", signo);
        request_stop();
    });

    return signals;
}

// All state transitions run on main_ctx. Data threads may only publish one
// failure notification, and remain in run() until their live owner has joined.
class RuntimeOwner {
public:
    explicit RuntimeOwner(BootstrapEnvironment& environment)
        : env(environment), main_work(net::make_work_guard(*env.main_ctx)),
          stop_event(*env.main_ctx, std::chrono::steady_clock::time_point::max()),
          monitor_loops{
              std::make_shared<common::MonitorLoop>(
                  env.main_ctx->get_executor(), "sampling",
                  [this] { return RuntimeSamplingLoop(); }, ReportMonitorExit),
              std::make_shared<common::MonitorLoop>(
                  env.main_ctx->get_executor(), "stats-output",
                  [this] { return RuntimeStatsOutputLoop(); }, ReportMonitorExit),
          } {}

    void StartMonitor() {
        try {
            for (const auto& loop : monitor_loops) loop->Start();
        } catch (...) {
            for (const auto& loop : monitor_loops) loop->RequestStop();
            throw;
        }
    }

    void RequestStop(bool failure = false) noexcept {
        if (failure) exit_code = EXIT_FAILURE;
        if (stopping) return;
        stopping = true;
        env.controller->RequestStop();
        for (const auto& loop : monitor_loops) loop->RequestStop();
        for (size_t i = 0; i < started_threads; ++i) env.worker_pool.workers[i]->RequestDrain();
        env.dns_worker->RequestStop();
        stop_event.cancel();
        IoErrorCode ignored;
        if (signals) signals->cancel(ignored);
    }

    void RecordFailure(std::exception_ptr error) noexcept {
        RequestStop(true);
        try {
            if (error) std::rethrow_exception(error);
        } catch (const std::exception& failure) {
            try { infra::Log::WriteConsole(infra::LogLevel::ERROR, std::format("Runtime failed: {}", failure.what())); } catch (...) {}
        } catch (...) {
            try { infra::Log::WriteConsole(infra::LogLevel::ERROR, "Runtime failed: unknown exception"); } catch (...) {}
        }
    }

    void PublishFailure(std::exception_ptr error) noexcept {
        if (failure_pending.exchange(true, std::memory_order_acq_rel)) return;
        try {
            net::post(*env.main_ctx, [this, error] { RecordFailure(error); });
        } catch (...) {
            common::FailRuntime("runtime-failure", "cannot notify lifecycle owner");
        }
    }

    net::awaitable<std::vector<WorkerRuntimeStatsSnapshot>>
    CollectWorkerRuntimeStats(bool include_resources) const {
        auto snapshots = co_await PostToEachWorker(env.main_ctx->get_executor(),
            env.worker_pool.workers, stopping,
            [include_resources](Worker& worker, size_t) {
                return worker.PostCall([&worker, include_resources] {
                    return worker.CollectRuntimeStats(include_resources);
                });
            });
        ThrowIfStopping(stopping);
        co_return snapshots;
    }

    net::awaitable<void> RuntimeSamplingLoop() {
        net::steady_timer timer(*env.main_ctx);
        struct WorkerActivitySample {
            uint64_t connections_total;
            uint64_t connections_active;
            uint64_t bytes_in;
            uint64_t bytes_out;
            uint64_t errors;
            uint32_t active_sessions;
            size_t udp_sockets;
            bool operator==(const WorkerActivitySample&) const = default;
        };
        struct IdleHeapState {
            std::optional<WorkerActivitySample> previous;
            bool collected = false;
        };
        std::vector<IdleHeapState> heap_states(env.worker_pool.workers.size());
        std::vector<Worker*> idle_workers;
        idle_workers.reserve(env.worker_pool.workers.size());
        auto last_log_flush_at = common::steady_clock::time_point{};
        while (true) {
            auto worker_snapshots = co_await CollectWorkerRuntimeStats(false);
            auto aggregate_stats = AggregateWorkerStats(worker_snapshots);
            env.stats->SampleNow(aggregate_stats);
            constexpr auto kAsyncLogFlushInterval = std::chrono::seconds(5);
            idle_workers.clear();
            for (size_t index = 0; index < worker_snapshots.size(); ++index) {
                const auto& snapshot = worker_snapshots[index];
                const WorkerActivitySample activity{
                    .connections_total = snapshot.stats.connections_total,
                    .connections_active = snapshot.stats.connections_active,
                    .bytes_in = snapshot.stats.bytes_in,
                    .bytes_out = snapshot.stats.bytes_out,
                    .errors = snapshot.stats.errors,
                    .active_sessions = snapshot.active_connections,
                    .udp_sockets = snapshot.udp_sockets,
                };
                auto& state = heap_states[index];
                if (!state.previous || *state.previous != activity) {
                    state.previous = activity;
                    state.collected = false;
                } else if (!state.collected) {
                    idle_workers.push_back(env.worker_pool.workers[index].get());
                }
            }
            if (!idle_workers.empty()) {
                try {
                    // Statistics quiet does not prove I/O quiescence. Native
                    // collection is safe because it never releases live blocks.
                    co_await PostToEachWorker(env.main_ctx->get_executor(), idle_workers,
                        stopping, [](Worker& worker, size_t) {
                            return worker.PostCall([] { common::CollectThreadHeap(); });
                        });
                    ThrowIfStopping(stopping);
                    for (const Worker* worker : idle_workers)
                        heap_states[worker->Id()].collected = true;
                    common::CollectThreadHeap();
                } catch (const std::exception& error) {
                    ThrowIfStopping(stopping);
                    LOG_CONSOLE_WARN("Idle thread heap collection skipped: {}", error.what());
                }
            }
            {
                const auto flush_now = common::steady_clock::now();
                if (last_log_flush_at.time_since_epoch().count() == 0 ||
                    flush_now - last_log_flush_at >= kAsyncLogFlushInterval) {
                    infra::Log::Flush();
                    last_log_flush_at = flush_now;
                }
            }
            timer.expires_after(std::chrono::seconds(1));
            auto [ec] = co_await timer.async_wait(net::as_tuple(net::use_awaitable));
            if (ec) break;
        }
    }

    net::awaitable<void> RuntimeStatsOutputLoop() {
        net::steady_timer timer(*env.main_ctx);
        while (true) {
            auto worker_snapshots = co_await CollectWorkerRuntimeStats(true);
            auto snapshot = env.stats->WithCurrentRate(AggregateWorkerStats(worker_snapshots));

            const auto dns_stats = co_await env.dns_worker->GetCacheStats();
            ThrowIfStopping(stopping);
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
            for (const auto& worker_snapshot : worker_snapshots) {
                total_udp_sockets += worker_snapshot.udp_sockets;
            }
            const auto total_users = UserStore::TotalUsers();
            LOG_CONSOLE("Runtime activity: conn={} users={} udp_sockets={}",
                        total_conns, total_users, total_udp_sockets);
            LOG_CONSOLE("Runtime memory: resident={:.1f}MB", mem_mb);
            LOG_CONSOLE("Runtime traffic: traffic_in={} traffic_out={} rate_down={} rate_up={}",
                        ::app::FormatBytes(snapshot.bytes_in), ::app::FormatBytes(snapshot.bytes_out),
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
                            worker.worker_id, worker.active_connections, worker.udp_sockets,
                            r.timeout_events, r.timeout_heap_capacity, r.timeout_waiters);
                LOG_CONSOLE("Worker UDP resources: id={} udp_listeners={} udp_receive_loops={} udp_resource_drops={} udp_associations={} udp_closed={} udp_reply_senders={}",
                            worker.worker_id, r.udp_listeners, r.udp_receive_loops, r.udp_resource_drops,
                            r.udp_associations, r.udp_closed_associations, r.udp_reply_senders);
                LOG_CONSOLE("Worker UDP traffic: id={} udp_input_packets={} udp_input_bytes={} udp_reply_packets={} udp_reply_bytes={} udp_native_dispatches={}",
                            worker.worker_id, r.udp_input_datagrams, r.udp_input_bytes,
                            r.udp_reply_datagrams, r.udp_reply_bytes, r.udp_native_dispatches);
            }

            auto node_stats = env.controller->GetNodeStats();
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
                    const infra::PanelLogContext log_context{ns.panel_name, ns.panel_host, ns.node_id, ns.node_type};
                    LOG_PANEL_DEBUG(log_context,
                        "Node activity: port={} network={} users={} online={} upload={} download={}",
                        ns.port,
                        ns.network,
                        ns.total_users,
                        ns.online_users,
                        ::app::FormatBytes(ns.bytes_up),
                        ::app::FormatBytes(ns.bytes_down));
                }
                LOG_CONSOLE("Panel node totals: count={} users={} online={} upload={} download={}",
                         node_stats.size(),
                         node_users,
                         node_online,
                         ::app::FormatBytes(node_up),
                         ::app::FormatBytes(node_down));
            }

            timer.expires_after(std::chrono::seconds(common::kStatsOutputInterval));
            auto [ec] = co_await timer.async_wait(net::as_tuple(net::use_awaitable));
            if (ec) break;
        }
    }

    net::awaitable<void> JoinMonitor() {
        co_await net::this_coro::reset_cancellation_state(net::disable_cancellation());
        for (const auto& loop : monitor_loops) co_await loop->AsyncJoin();
    }

    net::awaitable<void> Run() {
        co_await net::this_coro::reset_cancellation_state(net::disable_cancellation());
        const auto& workers = env.worker_pool.workers;
        if (!stopping) {
            try {
                co_await PostToEachWorkerInOrder(workers, stopping,
                    [this](Worker& worker, size_t) {
                        return worker.PostTask(StartWorkerInbounds(worker, env.inbound_startup));
                    });
                if (!stopping) {
                    if (env.enable_controller) env.controller->Start();
                    StartMonitor();
                    for (const auto& inbound : env.inbound_startup) {
                        LOG_CONSOLE("Static inbound ready: tag={} port={} protocol={} network={}",
                            inbound.binding.tag, inbound.binding.port, inbound.binding.protocol,
                            inbound.receiver.stream_settings.NetworkName());
                    }
                    env.inbound_startup.clear();
                    env.inbound_startup.shrink_to_fit();
                    LOG_CONSOLE("Server ready; server started workers={} accept=SO_REUSEPORT", workers.size());
                }
            } catch (const IoSystemError& error) {
                if (!stopping || error.code() != net::error::operation_aborted)
                    RecordFailure(std::current_exception());
            } catch (...) { RecordFailure(std::current_exception()); }
        }
        while (!stopping) {
            IoErrorCode ec;
            co_await stop_event.async_wait(net::redirect_error(net::use_awaitable, ec));
        }
        // Drain data tasks first, retaining bounded control admission for the
        // final durable accounting snapshot. Every owner still joins on failure.
        try { co_await env.controller->AsyncJoin(); }
        catch (...) { RecordFailure(std::current_exception()); }
        try { co_await JoinMonitor(); }
        catch (...) { RecordFailure(std::current_exception()); }
        for (size_t i = 0; i < started_threads; ++i) {
            try { co_await workers[i]->AsyncDrain(); }
            catch (...) { RecordFailure(std::current_exception()); }
        }
        try { co_await env.controller->FlushTraffic(); }
        catch (...) { RecordFailure(std::current_exception()); }
        auto coordinator = started_threads ? workers.front()->Coordinator() : nullptr;
        if (coordinator) {
            coordinator->CloseAdmission();
            try {
                co_await net::co_spawn(coordinator->Reactor(),
                    [coordinator]() -> net::awaitable<void> {
                        co_await coordinator->AsyncJoin();
                        coordinator->ReleaseServices();
                    }, net::use_awaitable);
            } catch (...) { RecordFailure(std::current_exception()); }
        }
        for (size_t i = 0; i < started_threads; ++i) workers[i]->RequestStop();
        for (size_t i = 0; i < started_threads; ++i) {
            bool joined = false;
            while (!joined) {
                try {
                    co_await workers[i]->AsyncJoin();
                    joined = true;
                } catch (...) { RecordFailure(std::current_exception()); }
            }
        }
        if (coordinator) {
            auto executor = coordinator->Reactor().get_executor();
            try {
                co_await net::co_spawn(executor,
                    [coordinator = std::move(coordinator)]() mutable -> net::awaitable<void> {
                        try {
                            co_await coordinator->Finalize();
                        } catch (...) {
                            coordinator.reset();
                            throw;
                        }
                        coordinator.reset();
                        co_return;
                    }, net::use_awaitable);
            } catch (...) { RecordFailure(std::current_exception()); }
        }
        for (size_t i = 0; i < started_threads; ++i) env.worker_pool.work_guards[i].reset();
        bool dns_joined = false;
        while (!dns_joined) {
            try {
                co_await env.dns_worker->AsyncJoin();
                dns_joined = true;
            } catch (...) { RecordFailure(std::current_exception()); }
        }
    }

    BootstrapEnvironment& env;
    net::executor_work_guard<net::io_context::executor_type> main_work;
    net::steady_timer stop_event;
    std::array<std::shared_ptr<common::MonitorLoop>, 2> monitor_loops;
    std::unique_ptr<net::signal_set> signals;
    size_t started_threads = 0;
    int exit_code = EXIT_SUCCESS;
    bool stopping = false;
    bool completed = false;
    std::atomic<bool> failure_pending{false};
};

void RunDataThread(RuntimeOwner& owner, size_t index) noexcept {
    auto& context = *owner.env.worker_pool.io_contexts[index];
    owner.env.worker_pool.workers[index]->RunEventLoop();
    // Live state and maintenance have already joined. Release cancels the
    // scheduler's final timer; drain that completion before destroying its
    // container capacity on this same thread.
    transport::TimeoutScheduler::ReleaseForIoContext(context);
    context.restart();
    for (;;) {
        try { context.run(); break; }
        catch (...) { owner.PublishFailure(std::current_exception()); }
    }
    owner.env.worker_pool.io_contexts[index].reset();
}

// Returns only after every live owner and fixed data thread has completed.
int RunApplicationRuntime(BootstrapEnvironment& env) noexcept {
    std::vector<std::thread> threads;
    try {
        RuntimeOwner owner(env);
        auto& main_ctx = *env.main_ctx;
        const auto& workers = env.worker_pool.workers;
        threads.reserve(workers.size());
        // The total lifecycle coroutine is owned before any data thread starts.
        net::co_spawn(main_ctx, owner.Run(), [&owner](std::exception_ptr error) {
            if (error) common::FailRuntime("runtime-join", "lifecycle completion failed");
            owner.completed = true;
            owner.main_work.reset();
        });
        try {
            owner.signals = InstallShutdownHandler(main_ctx, [&owner] { owner.RequestStop(); });
            for (size_t i = 0; i < workers.size(); ++i) {
                workers[i]->SetFailureHandler(&owner,
                    [](void* context, std::exception_ptr error) noexcept {
                        static_cast<RuntimeOwner*>(context)->PublishFailure(error);
                    });
                threads.emplace_back([&owner, i] { RunDataThread(owner, i); });
                ++owner.started_threads;
            }
        } catch (...) { owner.RecordFailure(std::current_exception()); }

        for (;;) {
            try {
                main_ctx.run();
                if (owner.completed) break;
                main_ctx.restart();
                owner.RecordFailure(std::make_exception_ptr(
                    std::runtime_error("main event loop stopped before lifecycle completion")));
            } catch (...) { owner.RecordFailure(std::current_exception()); }
        }
        // No join blocks an event loop needed by a data-thread completion.
        for (auto& thread : threads) thread.join();
        for (size_t i = owner.started_threads; i < env.worker_pool.work_guards.size(); ++i)
            env.worker_pool.work_guards[i].reset();
        transport::TimeoutScheduler::ReleaseForIoContext(main_ctx);
        main_ctx.restart();
        for (;;) {
            try { main_ctx.run(); break; }
            catch (...) { owner.RecordFailure(std::current_exception()); }
        }
        return owner.exit_code;
    } catch (...) {
        // Before the pre-owned lifecycle exists there are no data threads or
        // accepted startup jobs. An exception after that boundary is corruption
        // of the lifecycle itself and cannot unwind live thread owners.
        if (!threads.empty()) common::FailRuntime("runtime-owner", "lifecycle owner failed");
        return EXIT_FAILURE;
    }
}
}  // namespace

// ============================================================================
// RunFromCommandLine
// ============================================================================
int RunFromCommandLine(int argc, char* argv[]) {
    const CommandLineOptions cli = ParseCommandLine(argc, argv);
    if (cli.action == CommandLineAction::Help) {
        PrintUsage(std::cout, argv[0]);
        return 0;
    }
    if (cli.action == CommandLineAction::Version) {
        PrintVersion(std::cout);
        return 0;
    }
    if (cli.action == CommandLineAction::Error) {
        std::cerr << cli.error << "\n";
        PrintUsage(std::cerr, argv[0]);
        return 2;
    }

    bool config_error_reported = false;
    auto config_opt = LoadConfigFromCli(cli, config_error_reported);
    if (!config_opt) {
        if (!config_error_reported) {
            infra::Log::WriteConsole(infra::LogLevel::ERROR, std::format("Failed to load config from: {}", cli.config_path));
        }
        return 1;
    }
    const infra::Config& config = *config_opt;

    if (!infra::Log::Init(config.log)) {
        infra::Log::WriteConsole(infra::LogLevel::ERROR, "Failed to initialize logging");
        return 1;
    }
    LOG_CONSOLE("Configuration loaded: workers={} inbounds={} outbounds={} rules={} panels={}",
                config.workers,
                config.static_inbounds.size(),
                config.outbounds.size(),
                config.routing.rules.size(),
                config.panels.size());
    LOG_CONSOLE("Starting cnode v1.0.0: channel={} build={}", BUILD_CHANNEL, BUILD_ID);
    LOG_CONSOLE("Runtime configured: workers={} io={} accept=SO_REUSEPORT allocator=mimalloc-thread-heap",
                config.workers, IoBackendName());
    if (!infra::ValidateConfig(config)) {
        infra::Log::WriteConsole(infra::LogLevel::ERROR, "Invalid configuration");
        infra::Log::Shutdown();
        return 1;
    }

    int result = 1;
    try {
        // The environment owns every runtime copy; nothing reads the Config again.
        auto env = CreateBootstrapEnvironment(std::move(*config_opt), cli.test_mode);
        config_opt.reset();
        result = RunApplicationRuntime(env);
    } catch (const std::exception& e) {
        infra::Log::WriteConsole(infra::LogLevel::ERROR, std::format("Failed to initialize runtime: {}", e.what()));
        infra::Log::Shutdown();
        return 1;
    }
    infra::Log::Shutdown();
    return result;
}

}  // namespace app

