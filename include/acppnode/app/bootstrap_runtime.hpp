#pragma once
#include "acppnode/common/asio_types.hpp"
#include <asio/executor_work_guard.hpp>
#include <cstdint>
#include <optional>

namespace acpp {
class Controller;
class StatsSampler;
class Runtime;
namespace app::dns { class DNSService; }
struct InboundStartup;

using RuntimeWorkGuard =
    net::executor_work_guard<net::io_context::executor_type>;

struct RuntimeContext {
    net::io_context& io_context;
    std::optional<RuntimeWorkGuard>& work_guard;
    net::any_io_executor control_executor;
    net::any_io_executor monitor_executor;
    StatsSampler& stats_sampler;
    Runtime& runtime;
    Controller& controller;
    InboundStartup& inbound_startup;
    app::dns::DNSService& dns_service;
    uint32_t io_threads;
};

void RunApplicationRuntime(const RuntimeContext&);
}  // namespace acpp
