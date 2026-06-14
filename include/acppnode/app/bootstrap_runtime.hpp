#pragma once

#include "acppnode/common/asio_types.hpp"

#include <asio/executor_work_guard.hpp>

#include <memory>
#include <string>
#include <vector>

namespace acpp {
class Controller;
class ShardedStats;
class Worker;
}

namespace acpp {

struct RuntimeContext {
    net::io_context&                                      main_ctx;
    ShardedStats&                                         stats;
    std::vector<std::unique_ptr<Worker>>&                 workers;
    Controller&                                     controller;
    std::vector<std::unique_ptr<net::io_context>>&        io_contexts;
    std::vector<net::executor_work_guard<net::io_context::executor_type>>& work_guards;
    const std::vector<std::string>&                       static_inbound_tags;
    bool                                                  enable_controller = false;
};

struct RuntimeState {
    bool running = true;
};

void RunApplicationRuntime(const RuntimeContext& ctx);

}  // namespace acpp
