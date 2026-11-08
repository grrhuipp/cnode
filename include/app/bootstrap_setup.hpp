#pragma once

#include "app/bootstrap_inbounds.hpp"
#include "common/asio_types.hpp"

#include <asio/executor_work_guard.hpp>

#include <memory>
#include <string>
#include <vector>

struct Config;
class ShardedStats;
class Controller;
class Worker;
namespace app::dns {
class DNS;
class DNSWorker;
}
namespace geo {
class GeoDatabase;
}
struct RuntimeContext;
struct WorkerRuntimeConfig;


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
    BootstrapEnvironment();
    ~BootstrapEnvironment();
    BootstrapEnvironment(BootstrapEnvironment&&) noexcept;
    BootstrapEnvironment& operator=(BootstrapEnvironment&&) noexcept;
    BootstrapEnvironment(const BootstrapEnvironment&) = delete;
    BootstrapEnvironment& operator=(const BootstrapEnvironment&) = delete;

    std::unique_ptr<net::io_context> main_ctx;
    std::unique_ptr<app::dns::DNSWorker> dns_worker;
    std::unique_ptr<app::dns::DNS> panel_dns_service;
    std::unique_ptr<geo::GeoDatabase> geo_database;
    std::unique_ptr<ShardedStats> stats;
    WorkerPool worker_pool;
    std::unique_ptr<Controller> controller;
    InboundStartup inbound_startup;
    bool enable_controller = false;
};

[[nodiscard]] WorkerPool CreateWorkerPool(
    const WorkerRuntimeConfig& runtime_config,
    ShardedStats& stats,
    geo::GeoDatabase* geo_database,
    app::dns::DNSWorker& dns_worker);

[[nodiscard]] BootstrapEnvironment CreateBootstrapEnvironment(
    const Config& config,
    bool test_mode);

[[nodiscard]] RuntimeContext MakeRuntimeContext(BootstrapEnvironment& env);

