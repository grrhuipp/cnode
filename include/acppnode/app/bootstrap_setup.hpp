#pragma once

#include "acppnode/common/asio_types.hpp"

#include <asio/executor_work_guard.hpp>

#include <memory>
#include <string>
#include <vector>

namespace acpp {
class Config;
class ConnectionLimiter;
class ShardedStats;
class Controller;
class Worker;
namespace app::dns {
class DNS;
}
namespace geo {
class GeoManager;
}
struct RuntimeContext;
struct WorkerRuntimeConfig;
}

namespace acpp {

struct WorkerPool {
    // Destruction order is the reverse of this declaration:
    // work guards release first, io_contexts then destroy pending coroutine
    // frames, and Workers/handlers/validators remain alive for that cleanup.
    std::vector<std::unique_ptr<Worker>> workers;
    std::vector<std::unique_ptr<net::io_context>> io_contexts;
    std::vector<net::executor_work_guard<net::io_context::executor_type>> work_guards;
};

struct BootstrapEnvironment {
    BootstrapEnvironment();
    ~BootstrapEnvironment();
    BootstrapEnvironment(BootstrapEnvironment&&) noexcept;
    BootstrapEnvironment& operator=(BootstrapEnvironment&&) noexcept;
    BootstrapEnvironment(const BootstrapEnvironment&) = delete;
    BootstrapEnvironment& operator=(const BootstrapEnvironment&) = delete;

    std::unique_ptr<net::io_context> main_ctx;
    std::unique_ptr<app::dns::DNS> panel_dns_service;
    std::unique_ptr<geo::GeoManager> geo_manager;
    std::unique_ptr<ShardedStats> stats;
    std::vector<std::unique_ptr<ConnectionLimiter>> connection_limiters;
    WorkerPool worker_pool;
    std::unique_ptr<Controller> controller;
    std::vector<std::string> static_inbound_tags;
    bool enable_controller = false;
};

[[nodiscard]] WorkerPool CreateWorkerPool(
    const WorkerRuntimeConfig& runtime_config,
    ShardedStats& stats,
    geo::GeoManager* geo_manager);

[[nodiscard]] BootstrapEnvironment CreateBootstrapEnvironment(
    const Config& config,
    bool test_mode);

[[nodiscard]] RuntimeContext MakeRuntimeContext(BootstrapEnvironment& env);

}  // namespace acpp
