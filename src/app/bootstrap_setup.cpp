#include "acppnode/app/bootstrap_setup.hpp"
#include "startup_inbounds.hpp"

#include "acppnode/app/bootstrap_inbounds.hpp"
#include "acppnode/app/bootstrap_panels.hpp"
#include "acppnode/app/bootstrap_runtime.hpp"
#include "acppnode/app/dns/dns.hpp"
#include "acppnode/app/dns/dns_service.hpp"
#include "acppnode/infra/config.hpp"
#include "acppnode/app/rate_limiter.hpp"
#include "acppnode/app/proxyman/inbound/user_store.hpp"
#include "acppnode/runtime/runtime.hpp"
#include "acppnode/runtime/runtime_config.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/service/controller/controller.hpp"
#include "acppnode/app/stats.hpp"
#include "acppnode/geo/geodata.hpp"
#include "acppnode/transport/internet/timeout_scheduler.hpp"
#include "acppnode/transport/internet/transport_stack.hpp"

#include <asio/strand.hpp>
#include <algorithm>
#include <filesystem>
#include <format>
#include <stdexcept>

namespace acpp {

BootstrapEnvironment::BootstrapEnvironment() = default;
BootstrapEnvironment::~BootstrapEnvironment() = default;
BootstrapEnvironment::BootstrapEnvironment(BootstrapEnvironment&&) noexcept = default;

namespace {

::acpp::app::dns::Config MakeDnsServiceConfig(const Config& config) {
    ::acpp::app::dns::Config dns_config;
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
    const auto geoip_tags = config.GetUsedGeoIPTags();
    const auto geosite_tags = config.GetUsedGeoSiteTags();

    if (!geoip_tags.empty() && !std::filesystem::exists(geoip_path)) {
        throw std::runtime_error(std::format(
            "routing geoip tags require '{}'", geoip_path.string()));
    }
    if (!geosite_tags.empty() && !std::filesystem::exists(geosite_path)) {
        throw std::runtime_error(std::format(
            "routing geosite tags require '{}'", geosite_path.string()));
    }

    if (!std::filesystem::exists(geoip_path) && !std::filesystem::exists(geosite_path)) {
        return geo_manager;
    }

    geo_manager = std::make_unique<geo::GeoManager>();
    if (geo_manager->Init(geoip_path, geosite_path)) {
        geo_manager->PreloadTags(geoip_tags, geosite_tags);
        for (const auto& tag : geoip_tags) {
            if (!geo_manager->ResolveGeoIPTag(tag).Valid()) {
                throw std::runtime_error(std::format(
                    "routing geoip tag '{}' was not loaded from '{}'",
                    tag, geoip_path.string()));
            }
        }
        for (const auto& tag : geosite_tags) {
            if (!geo_manager->ResolveGeoSiteTag(tag).Valid()) {
                throw std::runtime_error(std::format(
                    "routing geosite tag '{}' was not loaded from '{}'",
                    tag, geosite_path.string()));
            }
        }
        auto gs = geo_manager->GetStats();
        LOG_CONSOLE("geodata ready geoip_tags={} geosite_tags={}",
                    gs.geoip_tags_loaded, gs.geosite_tags_loaded);
    } else {
        throw std::runtime_error("geodata initialization failed");
    }
    return geo_manager;
}

std::unique_ptr<ConnectionLimiter> CreateConnectionLimiter(
    const Config& config, net::any_io_executor executor) {
    RateLimitConfig limits;
    limits.max_connections = config.GetLimits().max_connections;
    limits.max_conn_per_ip = config.GetLimits().max_connections_per_ip;
    return std::make_unique<ConnectionLimiter>(std::move(executor), limits);
}

uint32_t ComputePressureThreshold(const RuntimeConfig& config) {
    uint32_t threshold = defaults::kMaxConnectionsPerRuntime
        * defaults::kPressurePercent / 100;

    const uint32_t configured_max = config.limits.max_connections;

    if (configured_max > 0) {
        const uint32_t runtime_budget = std::max<uint32_t>(
            1, configured_max);
        const uint32_t configured_threshold = std::max<uint32_t>(
            1, runtime_budget * defaults::kPressurePercent / 100);
        threshold = std::min(threshold, configured_threshold);
    }

    return std::max<uint32_t>(threshold, 1);
}

uint32_t ComputePressureIdleTimeout(const RuntimeConfig& config) {
    return config.timeouts.idle > defaults::kPressureIdleTimeout
        ? defaults::kPressureIdleTimeout
        : 0;
}

RuntimeConfig MakeRuntimeConfig(
    const Config& config, const std::vector<PreparedStartupInbound>& inbounds) {
    RuntimeConfig runtime_config;
    runtime_config.timeouts = config.GetTimeouts();
    runtime_config.limits = config.GetLimits();
    runtime_config.routing = config.GetRouting();
    runtime_config.static_inbounds.reserve(inbounds.size());
    for (const auto& inbound : inbounds) {
        runtime_config.static_inbounds.push_back(inbound.runtime);
    }
    runtime_config.outbounds = config.GetPreparedOutbounds();
    runtime_config.pressure_threshold = ComputePressureThreshold(runtime_config);
    runtime_config.pressure_idle_timeout = ComputePressureIdleTimeout(runtime_config);
    return runtime_config;
}

}  // namespace

BootstrapEnvironment CreateBootstrapEnvironment(
    const Config& config,
    bool test_mode) {
    BootstrapEnvironment env;
    const bool enable_test_mode =
        test_mode || (config.GetPanels().empty() && config.GetStaticInbounds().empty());
    const auto inbounds = PrepareStartupInbounds(config.GetStaticInbounds(), enable_test_mode);
    env.io_context = std::make_unique<net::io_context>();
    TimeoutScheduler::Install(env.io_context->get_executor());
    InstallXHttpSessionService(env.io_context->get_executor());
    env.work_guard.emplace(net::make_work_guard(*env.io_context));
    env.control_executor = net::make_strand(*env.io_context);
    env.monitor_executor = net::make_strand(*env.io_context);
    env.io_threads = std::max<uint32_t>(1, config.GetIoThreads());
    env.dns_service = std::make_unique<app::dns::DNSService>(
        net::make_strand(*env.io_context), MakeDnsServiceConfig(config), defaults::kServiceChannelCapacity);
    env.panel_dns_service = std::make_unique<app::dns::DNS>(*env.dns_service);
    env.geo_manager = CreateGeoManager(config);
    env.stats = std::make_unique<StatsShard>();
    env.stats_sampler = std::make_unique<StatsSampler>();
    env.connection_limiter = CreateConnectionLimiter(config, net::make_strand(*env.io_context));
    const RuntimeConfig runtime_config = MakeRuntimeConfig(config, inbounds);
    env.runtime = std::make_unique<Runtime>(
        env.io_context->get_executor(), runtime_config, *env.stats,
        *env.dns_service, env.geo_manager.get());
    env.controller = std::make_unique<Controller>(
        env.control_executor, *env.runtime, *env.connection_limiter);

    SetupPanels(env.control_executor, *env.controller, config, *env.panel_dns_service);
    // Every source and protocol payload is prepared before one RCU publication.
    // These borrowed references stay in this synchronous cold-path call.
    std::vector<proxyman::inbound::UserStore::UserUpdate> user_updates;
    user_updates.reserve(inbounds.size());
    for (const auto& inbound : inbounds) {
        user_updates.push_back({inbound.runtime.tag, inbound.users});
    }
    proxyman::inbound::UserStore::ApplyUsers(user_updates);
    if (enable_test_mode) {
        LOG_CONSOLE("test_mode enabled port={} uuid={}",
                    constants::test::kTestPort, constants::test::kTestVmessUuid);
    }
    env.inbound_startup = InboundStartup{
        runtime_config.static_inbounds, env.connection_limiter.get()};

    return env;
}

RuntimeContext MakeRuntimeContext(BootstrapEnvironment& env) {
    return RuntimeContext{
        *env.io_context, env.work_guard, env.control_executor, env.monitor_executor,
        *env.stats_sampler, *env.runtime, *env.controller, env.inbound_startup,
        *env.dns_service, env.io_threads};
}

}  // namespace acpp
