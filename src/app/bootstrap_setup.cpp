#include "app/bootstrap_setup.hpp"
#include "startup_inbounds.hpp"

#include "app/bootstrap_inbounds.hpp"
#include "app/bootstrap_panels.hpp"
#include "app/bootstrap_runtime.hpp"
#include "app/dns/dns.hpp"
#include "app/dns/dns_worker.hpp"
#include "infra/config.hpp"
#include "app/proxyman/inbound/user_store.hpp"
#include "app/runtime_publication.hpp"
#include "proxyman/outbound/registration.hpp"
#include "app/worker.hpp"
#include "app/session_group_executor.hpp"
#include "app/worker_runtime_config.hpp"
#include "infra/log.hpp"
#include "service/controller/controller.hpp"
#include "app/stats.hpp"
#include "geo/geodata.hpp"
#include "transport/internet/tls_stream.hpp"

#include <asio/co_spawn.hpp>
#include <asio/use_future.hpp>

#include <algorithm>
#include <filesystem>
#include <format>
#include <limits>
#include <optional>
#include <stdexcept>


BootstrapEnvironment::BootstrapEnvironment() = default;
BootstrapEnvironment::~BootstrapEnvironment() = default;
BootstrapEnvironment::BootstrapEnvironment(BootstrapEnvironment&&) noexcept = default;
BootstrapEnvironment& BootstrapEnvironment::operator=(BootstrapEnvironment&&) noexcept = default;

namespace {

::app::dns::Config MakeDnsServiceConfig(const Config& config) {
    ::app::dns::Config dns_config;
    dns_config.servers     = config.dns.servers;
    dns_config.timeout_sec = config.dns.timeout;
    dns_config.cache_size  = config.dns.cache_size;
    dns_config.min_ttl     = config.dns.min_ttl;
    dns_config.max_ttl     = config.dns.max_ttl;
    return dns_config;
}

// 只有路由实际引用 geo 分类时才加载数据；未引用时 Router 不需要 GeoDatabase。
std::unique_ptr<geo::GeoDatabase> LoadGeoDatabase(const Config& config) {
    const auto geoip_tags = GetUsedGeoIPTags(config.routing);
    const auto geosite_tags = GetUsedGeoSiteTags(config.routing);
    if (geoip_tags.empty() && geosite_tags.empty()) {
        return nullptr;
    }

    const auto geoip_path   = config.config_dir / constants::paths::kGeoIpFile;
    const auto geosite_path = config.config_dir / constants::paths::kGeoSiteFile;
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
        static_cast<uint64_t>(defaults::kMaxConnectionsPerWorker) * workers,
        std::numeric_limits<uint32_t>::max());
    uint32_t effective_max = static_cast<uint32_t>(scaled_default);
    if (configured_max > 0) {
        effective_max = std::min(effective_max, configured_max);
    }
    return std::max<uint32_t>(
        1, static_cast<uint32_t>(
               static_cast<uint64_t>(effective_max) * defaults::kPressurePercent / 100));
}

uint32_t ComputePressureIdleTimeout(const WorkerRuntimeConfig& config) {
    return config.timeouts.idle > defaults::kPressureIdleTimeout
        ? defaults::kPressureIdleTimeout
        : 0;
}

std::vector<proxyman::outbound::PreparedOutboundConfig> PrepareStartupOutbounds(
    std::span<const infra::OutboundSourceConfig> sources) {
    std::vector<proxyman::outbound::PreparedOutboundConfig> prepared;
    prepared.reserve(sources.size());
    for (const auto& raw_config : sources) {
        auto item = proxyman::outbound::PrepareOutboundConfig(raw_config);
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
    const Config& config,
    std::vector<proxyman::outbound::PreparedOutboundConfig> outbounds) {
    WorkerRuntimeConfig runtime_config;
    runtime_config.timeouts = config.timeouts;
    runtime_config.limits = config.limits;
    runtime_config.routing = config.routing;
    runtime_config.outbounds = std::move(outbounds);
    runtime_config.workers = config.workers;
    runtime_config.pressure_threshold = ComputePressureThreshold(runtime_config);
    runtime_config.pressure_idle_timeout = ComputePressureIdleTimeout(runtime_config);
    return runtime_config;
}

}  // namespace

WorkerPool CreateWorkerPool(const WorkerRuntimeConfig& runtime_config,
                            ShardedStats& stats,
                            geo::GeoDatabase* geo_database,
                            app::dns::DNSWorker& dns_worker) {
    WorkerPool pool;
    const uint32_t workers = std::max<uint32_t>(1, runtime_config.workers);
    pool.workers.reserve(workers);
    pool.io_contexts.reserve(workers);
    pool.work_guards.reserve(workers);

    for (uint32_t i = 0; i < workers; ++i) {
        pool.io_contexts.push_back(
            std::make_unique<net::io_context>());
        pool.work_guards.push_back(net::make_work_guard(*pool.io_contexts[i]));
        auto& worker_stats = stats.GetShard(i);
        pool.workers.push_back(std::make_unique<Worker>(
            i, *pool.io_contexts[i], runtime_config, worker_stats, dns_worker,
            geo_database));
    }
    auto coordinator = std::make_shared<GroupCoordinator>(*pool.io_contexts.front());
    for (const auto& worker : pool.workers) worker->SetGroupCoordinator(coordinator);

    return pool;
}

BootstrapEnvironment CreateBootstrapEnvironment(
    const Config& config,
    bool test_mode) {
    TlsStream::InitializeIo();
    BootstrapEnvironment env;
    const bool enable_test_mode =
        test_mode || (config.panels.empty() && config.static_inbounds.empty());
    auto outbounds = PrepareStartupOutbounds(config.outbounds);
    auto inbounds = PrepareStartupInbounds(config.static_inbounds, enable_test_mode);
    constexpr int kMainIoConcurrencyHint =
        static_cast<int>(ASIO_CONCURRENCY_HINT_ID | ASIO_CONCURRENCY_HINT_LOCKING_SCHEDULER);
    env.main_ctx = std::make_unique<net::io_context>(kMainIoConcurrencyHint);
    env.dns_worker = std::make_unique<app::dns::DNSWorker>(
        *env.main_ctx, MakeDnsServiceConfig(config), defaults::kWorkerMailboxCapacity);
    env.panel_dns_service = std::make_unique<app::dns::DNS>(*env.dns_worker);
    env.geo_database = LoadGeoDatabase(config);
    env.stats = std::make_unique<ShardedStats>(config.workers);
    const WorkerRuntimeConfig worker_runtime_config =
        MakeWorkerRuntimeConfig(config, std::move(outbounds));
    // Every source and protocol payload is prepared before one RCU publication.
    // Workers do not exist yet: each captures the committed snapshot when it is
    // constructed below. These borrowed references stay in this call.
    std::vector<proxyman::inbound::UserStore::UserUpdate> user_updates;
    user_updates.reserve(inbounds.size());
    for (const auto& inbound : inbounds) {
        user_updates.push_back({inbound.binding.tag, *inbound.users});
    }
    const auto previous_users = proxyman::inbound::UserStore::CaptureSnapshot();
    {
        constexpr bool kNotStopping = false;
        std::optional<UserPublicationRollback> rollback;
        net::io_context publication_ctx;
        auto published = net::co_spawn(publication_ctx,
            PublishUsers(publication_ctx.get_executor(), {},
                proxyman::inbound::UserStore::PrepareUsers(user_updates),
                rollback, kNotStopping),
            net::use_future);
        publication_ctx.run();
        published.get();
    }
    try {
        env.worker_pool = CreateWorkerPool(
            worker_runtime_config, *env.stats, env.geo_database.get(), *env.dns_worker);
        env.controller = std::make_unique<Controller>(
            *env.main_ctx, env.worker_pool.workers);

        SetupPanels(*env.main_ctx, *env.controller, config, *env.panel_dns_service);
        if (enable_test_mode) {
            LOG_CONSOLE("Test mode enabled: port={}", constants::test::kTestPort);
        }
        env.inbound_startup.entries = std::move(inbounds);

        env.enable_controller = !config.panels.empty();
        return env;
    } catch (...) {
        proxyman::inbound::UserStore::CommitSnapshot(previous_users);
        throw;
    }
}

RuntimeContext MakeRuntimeContext(BootstrapEnvironment& env) {
    return RuntimeContext{
        *env.main_ctx,
        *env.stats,
        env.worker_pool.workers,
        *env.controller,
        env.worker_pool.io_contexts,
        env.inbound_startup,
        *env.dns_worker,
        env.worker_pool.work_guards,
        env.enable_controller,
    };
}

