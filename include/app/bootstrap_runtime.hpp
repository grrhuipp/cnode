#pragma once

#include "common/asio_types.hpp"
#include <asio/executor_work_guard.hpp>

#include <memory>
#include <vector>

class Controller;
class ShardedStats;
class Worker;
namespace app::dns { class DNSWorker; }
struct InboundStartup;


struct RuntimeContext {
    net::io_context& main_ctx;
    ShardedStats& stats;
    const std::vector<std::unique_ptr<Worker>>& workers;
    Controller& controller;
    std::vector<std::unique_ptr<net::io_context>>& io_contexts;
    InboundStartup& inbound_startup;
    app::dns::DNSWorker& dns_worker;
    std::vector<net::executor_work_guard<net::io_context::executor_type>>& work_guards;
    bool enable_controller = false;
};

// Returns only after every live owner and fixed data thread has completed.
int RunApplicationRuntime(const RuntimeContext& ctx) noexcept;

