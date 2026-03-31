#pragma once

#include "acppnode/common.hpp"

namespace acpp {
class ConnectionLimiter;
class ShardedStats;
class PanelSyncManager;
namespace geo {
class GeoManager;
}
struct RuntimeContext;
}

namespace acpp {

struct WorkerPool {
    std::vector<std::unique_ptr<net::io_context>> io_contexts;
    std::vector<net::executor_work_guard<net::io_context::executor_type>> work_guards;
    std::vector<std::unique_ptr<Worker>> workers;
};

struct BootstrapEnvironment {
    std::unique_ptr<net::io_context> main_ctx;
    std::unique_ptr<geo::GeoManager> geo_manager;
    std::unique_ptr<ShardedStats> stats;
    std::shared_ptr<ConnectionLimiter> connection_limiter;
    WorkerPool worker_pool;
    std::unique_ptr<PanelSyncManager> sync_manager;
    std::vector<std::string> static_inbound_tags;
    bool enable_panel_sync = false;
};

[[nodiscard]] WorkerPool CreateWorkerPool(
    const Config& config,
    ShardedStats& stats,
    geo::GeoManager* geo_manager);

[[nodiscard]] BootstrapEnvironment CreateBootstrapEnvironment(
    const Config& config,
    bool test_mode);

[[nodiscard]] RuntimeContext MakeRuntimeContext(BootstrapEnvironment& env);

}  // namespace acpp
