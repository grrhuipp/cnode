#include "acppnode/app/bootstrap_setup.hpp"

#include "acppnode/app/bootstrap_inbounds.hpp"
#include "acppnode/app/bootstrap_panels.hpp"
#include "acppnode/app/bootstrap_runtime.hpp"
#include "acppnode/app/dns/dns.hpp"
#include "acppnode/infra/config.hpp"
#include "acppnode/app/rate_limiter.hpp"
#include "acppnode/app/static_inbound_runtime.hpp"
#include "acppnode/app/worker.hpp"
#include "acppnode/app/worker_runtime_config.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/service/controller/controller.hpp"
#include "acppnode/app/stats.hpp"
#include "acppnode/geo/geodata.hpp"

#include <algorithm>
#include <filesystem>

namespace acpp {

BootstrapEnvironment::BootstrapEnvironment() = default;
BootstrapEnvironment::~BootstrapEnvironment() = default;
BootstrapEnvironment::BootstrapEnvironment(BootstrapEnvironment&&) noexcept = default;
BootstrapEnvironment& BootstrapEnvironment::operator=(BootstrapEnvironment&&) noexcept = default;

namespace {

::acpp::app::dns::DNS::Config MakeDnsServiceConfig(const Config& config) {
    ::acpp::app::dns::DNS::Config dns_config;
    dns_config.servers     = config.GetDns().servers;
    dns_config.timeout_sec = config.GetDns().timeout;
    dns_config.cache_size  = config.GetDns().cache_size;
    dns_config.min_ttl     = config.GetDns().min_ttl;
    dns_config.max_ttl     = config.GetDns().max_ttl;
    return dns_config;
}

std::unique_ptr<geo::GeoManager> CreateGeoManager(const Config& config) {
    std::unique_ptr<geo::GeoManager> geo_manager;
    auto geoip_path   = config.GetConfigDir() / constants::paths::kGeoIpFile;
    auto geosite_path = config.GetConfigDir() / constants::paths::kGeoSiteFile;

    if (!std::filesystem::exists(geoip_path) && !std::filesystem::exists(geosite_path)) {
        return geo_manager;
    }

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
    return geo_manager;
}

std::vector<std::unique_ptr<ConnectionLimiter>> CreateConnectionLimiters(const Config& config) {
    const uint32_t workers = std::max<uint32_t>(1, config.GetWorkers());
    const auto split_budget = [workers](uint32_t value) -> uint32_t {
        if (value == 0) return 0;
        return std::max<uint32_t>(1, (value + workers - 1) / workers);
    };

    RateLimitConfig limiter_cfg;
    limiter_cfg.max_connections = split_budget(config.GetLimits().max_connections);
    limiter_cfg.max_conn_per_ip = split_budget(config.GetLimits().max_connections_per_ip);

    std::vector<std::unique_ptr<ConnectionLimiter>> limiters;
    limiters.reserve(workers);
    for (uint32_t i = 0; i < workers; ++i) {
        limiters.push_back(std::make_unique<ConnectionLimiter>(limiter_cfg));
    }
    return limiters;
}

uint32_t ComputePressureThreshold(const WorkerRuntimeConfig& config) {
    uint32_t threshold = defaults::kMaxConnectionsPerWorker
        * defaults::kPressurePercent / 100;

    const uint32_t configured_max = config.limits.max_connections;
    const uint32_t workers = std::max<uint32_t>(1, config.workers);
    if (configured_max > 0) {
        const uint32_t per_worker_budget = std::max<uint32_t>(
            1, (configured_max + workers - 1) / workers);
        const uint32_t configured_threshold = std::max<uint32_t>(
            1, per_worker_budget * defaults::kPressurePercent / 100);
        threshold = std::min(threshold, configured_threshold);
    }

    return std::max<uint32_t>(threshold, 1);
}

uint32_t ComputePressureIdleTimeout(const WorkerRuntimeConfig& config) {
    return config.timeouts.idle > defaults::kPressureIdleTimeout
        ? defaults::kPressureIdleTimeout
        : 0;
}

WorkerRuntimeConfig MakeWorkerRuntimeConfig(const Config& config) {
    WorkerRuntimeConfig runtime_config;
    runtime_config.dns = MakeDnsServiceConfig(config);
    runtime_config.timeouts = config.GetTimeouts();
    runtime_config.limits = config.GetLimits();
    runtime_config.routing = config.GetRouting();
    runtime_config.static_inbounds = BuildStaticInboundRuntimeEntries(config.GetStaticInbounds());
    runtime_config.inbound_users.reserve(runtime_config.static_inbounds.size());
    for (const auto& inbound : runtime_config.static_inbounds) {
        runtime_config.inbound_users.push_back(InboundUsersRuntimeEntry{
            inbound.protocol,
            inbound.tag,
            inbound.users,
        });
    }
    runtime_config.outbounds = config.GetPreparedOutbounds();
    runtime_config.workers = config.GetWorkers();
    runtime_config.pressure_threshold = ComputePressureThreshold(runtime_config);
    runtime_config.pressure_idle_timeout = ComputePressureIdleTimeout(runtime_config);
    return runtime_config;
}

}  // namespace

WorkerPool CreateWorkerPool(const WorkerRuntimeConfig& runtime_config,
                            ShardedStats& stats,
                            geo::GeoManager* geo_manager) {
    WorkerPool pool;
    const uint32_t workers = std::max<uint32_t>(1, runtime_config.workers);
    pool.io_contexts.reserve(workers);
    pool.work_guards.reserve(workers);
    pool.workers.reserve(workers);

    for (uint32_t i = 0; i < workers; ++i) {
        pool.io_contexts.push_back(std::make_unique<net::io_context>());
        pool.work_guards.push_back(net::make_work_guard(*pool.io_contexts[i]));
        auto& worker_stats = stats.GetShard(i);
        pool.workers.push_back(std::make_unique<Worker>(
            i, *pool.io_contexts[i], runtime_config, worker_stats, geo_manager));
    }

    return pool;
}

BootstrapEnvironment CreateBootstrapEnvironment(
    const Config& config,
    bool test_mode) {
    BootstrapEnvironment env;
    env.main_ctx = std::make_unique<net::io_context>();
    env.panel_dns_service = std::make_unique<app::dns::DNS>(
        *env.main_ctx, MakeDnsServiceConfig(config));
    env.geo_manager = CreateGeoManager(config);
    env.stats = std::make_unique<ShardedStats>(config.GetWorkers());
    env.connection_limiters = CreateConnectionLimiters(config);
    const WorkerRuntimeConfig worker_runtime_config = MakeWorkerRuntimeConfig(config);
    env.worker_pool = CreateWorkerPool(worker_runtime_config, *env.stats, env.geo_manager.get());
    env.controller = std::make_unique<Controller>(
        *env.main_ctx, env.worker_pool.workers, env.connection_limiters);

    SetupPanels(*env.main_ctx, *env.controller, config, *env.panel_dns_service);
    env.static_inbound_tags = SetupStaticInbounds(
        worker_runtime_config.static_inbounds, env.worker_pool.workers, env.connection_limiters);

    if (test_mode || (config.GetPanels().empty() && config.GetStaticInbounds().empty())) {
        SetupTestMode(env.worker_pool.workers, env.connection_limiters);
    }

    env.enable_controller = !config.GetPanels().empty();
    return env;
}

RuntimeContext MakeRuntimeContext(BootstrapEnvironment& env) {
    return RuntimeContext{
        *env.main_ctx,
        *env.stats,
        env.worker_pool.workers,
        *env.controller,
        env.worker_pool.io_contexts,
        env.worker_pool.work_guards,
        env.static_inbound_tags,
        env.enable_controller,
    };
}

}  // namespace acpp
