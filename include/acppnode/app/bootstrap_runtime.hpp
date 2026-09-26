#pragma once

#include "acppnode/common/asio_types.hpp"

#include <memory>
#include <vector>

namespace acpp {
class Controller;
class ShardedStats;
class Worker;
namespace app::dns { class DNSWorker; }
struct InboundStartup;
}

namespace acpp {

struct RuntimeContext {
    net::io_context& main_ctx;
    ShardedStats& stats;
    const std::vector<std::unique_ptr<Worker>>& workers;
    Controller& controller;
    const std::vector<std::unique_ptr<net::io_context>>& io_contexts;
    InboundStartup& inbound_startup;
    app::dns::DNSWorker& dns_worker;
    bool enable_controller = false;
};

// Transfers control to the process-lifetime runtime; never unwinds active Workers.
[[noreturn]] void RunApplicationRuntime(const RuntimeContext& ctx) noexcept;

}  // namespace acpp
