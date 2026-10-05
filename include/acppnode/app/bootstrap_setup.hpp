#pragma once

#include "acppnode/app/bootstrap_inbounds.hpp"
#include "acppnode/common/asio_types.hpp"
#include <asio/executor_work_guard.hpp>
#include <memory>
#include <optional>

namespace acpp {
class Config;
class ConnectionLimiter;
class StatsSampler;
struct StatsShard;
class Controller;
class Runtime;
namespace app::dns { class DNS; class DNSService; }
namespace geo { class GeoManager; }
struct RuntimeContext;

struct BootstrapEnvironment {
    BootstrapEnvironment();
    ~BootstrapEnvironment();
    BootstrapEnvironment(BootstrapEnvironment&&) noexcept;
    BootstrapEnvironment& operator=(BootstrapEnvironment&&) = delete;
    BootstrapEnvironment(const BootstrapEnvironment&) = delete;
    BootstrapEnvironment& operator=(const BootstrapEnvironment&) = delete;

    // Context outlives every service, queued operation and work reservation.
    std::unique_ptr<net::io_context> io_context;
    std::optional<net::executor_work_guard<net::io_context::executor_type>> work_guard;
    net::any_io_executor control_executor;
    net::any_io_executor monitor_executor;
    std::unique_ptr<app::dns::DNSService> dns_service;
    std::unique_ptr<app::dns::DNS> panel_dns_service;
    std::unique_ptr<geo::GeoManager> geo_manager;
    std::unique_ptr<StatsShard> stats;
    std::unique_ptr<StatsSampler> stats_sampler;
    std::unique_ptr<ConnectionLimiter> connection_limiter;
    std::unique_ptr<Runtime> runtime;
    std::unique_ptr<Controller> controller;
    InboundStartup inbound_startup;
    uint32_t io_threads = 1;
};

[[nodiscard]] BootstrapEnvironment CreateBootstrapEnvironment(const Config&, bool test_mode);
[[nodiscard]] RuntimeContext MakeRuntimeContext(BootstrapEnvironment&);
}  // namespace acpp
