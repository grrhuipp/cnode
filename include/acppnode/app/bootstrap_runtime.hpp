#pragma once

#include "acppnode/common.hpp"

namespace acpp {
class PanelSyncManager;
class ShardedStats;
class Worker;
}

namespace acpp {

struct RuntimeContext {
    net::io_context&                                      main_ctx;
    ShardedStats&                                         stats;
    std::vector<std::unique_ptr<Worker>>&                 workers;
    PanelSyncManager&                                     sync_manager;
    std::vector<std::unique_ptr<net::io_context>>&        io_contexts;
    std::vector<net::executor_work_guard<net::io_context::executor_type>>& work_guards;
    const std::vector<std::string>&                       static_inbound_tags;
    bool                                                  enable_panel_sync = false;
};

void RunApplicationRuntime(const RuntimeContext& ctx);

}  // namespace acpp
