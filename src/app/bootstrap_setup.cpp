#include "acppnode/app/bootstrap_setup.hpp"

#include "acppnode/app/bootstrap_inbounds.hpp"
#include "acppnode/app/bootstrap_panels.hpp"
#include "acppnode/app/bootstrap_runtime.hpp"
#include "acppnode/infra/config.hpp"
#include "acppnode/app/rate_limiter.hpp"
#include "acppnode/app/worker.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/app/panel_sync.hpp"
#include "acppnode/app/stats.hpp"
#include "acppnode/geo/geodata.hpp"

#include <filesystem>

namespace acpp {

namespace {

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

std::shared_ptr<ConnectionLimiter> CreateConnectionLimiter(const Config& config) {
    RateLimitConfig limiter_cfg;
    limiter_cfg.max_connections = config.GetLimits().max_connections;
    limiter_cfg.max_conn_per_ip = config.GetLimits().max_connections_per_ip;
    return std::make_shared<ConnectionLimiter>(limiter_cfg);
}

}  // namespace

WorkerPool CreateWorkerPool(const Config& config,
                            ShardedStats& stats,
                            geo::GeoManager* geo_manager) {
    WorkerPool pool;
    pool.io_contexts.reserve(config.GetWorkers());
    pool.work_guards.reserve(config.GetWorkers());
    pool.workers.reserve(config.GetWorkers());

    for (uint32_t i = 0; i < config.GetWorkers(); ++i) {
        pool.io_contexts.push_back(std::make_unique<net::io_context>());
        pool.work_guards.push_back(net::make_work_guard(*pool.io_contexts[i]));
        pool.workers.push_back(std::make_unique<Worker>(
            i, *pool.io_contexts[i], config, stats, geo_manager));
    }

    return pool;
}

BootstrapEnvironment CreateBootstrapEnvironment(
    const Config& config,
    bool test_mode) {
    BootstrapEnvironment env;
    env.main_ctx = std::make_unique<net::io_context>();
    env.geo_manager = CreateGeoManager(config);
    env.stats = std::make_unique<ShardedStats>(config.GetWorkers());
    env.connection_limiter = CreateConnectionLimiter(config);
    env.worker_pool = CreateWorkerPool(config, *env.stats, env.geo_manager.get());
    env.sync_manager = std::make_unique<PanelSyncManager>(
        *env.main_ctx, env.worker_pool.workers, env.connection_limiter);

    SetupPanels(*env.main_ctx, *env.sync_manager, config);
    env.static_inbound_tags = SetupStaticInbounds(
        config, env.worker_pool.workers, env.connection_limiter);

    if (test_mode || (config.GetPanels().empty() && config.GetInbounds().empty())) {
        SetupTestMode(env.worker_pool.workers, env.connection_limiter);
    }

    env.enable_panel_sync = !config.GetPanels().empty();
    return env;
}

RuntimeContext MakeRuntimeContext(BootstrapEnvironment& env) {
    return RuntimeContext{
        *env.main_ctx,
        *env.stats,
        env.worker_pool.workers,
        *env.sync_manager,
        env.worker_pool.io_contexts,
        env.worker_pool.work_guards,
        env.static_inbound_tags,
        env.enable_panel_sync,
    };
}

}  // namespace acpp
