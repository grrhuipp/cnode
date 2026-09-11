#pragma once

#include "acppnode/app/static_inbound_prepared_config.hpp"

#include <future>
#include <memory>
#include <vector>

namespace acpp {

class ConnectionLimiter;
class Worker;
struct InboundStartup {
    std::vector<StaticInboundRuntimeEntry> entries;
    std::vector<std::future<void>> worker_results;
};

[[nodiscard]] InboundStartup QueueInboundStartup(
    const std::vector<StaticInboundRuntimeEntry>& runtime_inbounds,
    const std::vector<std::unique_ptr<Worker>>& workers,
    const std::vector<std::unique_ptr<ConnectionLimiter>>& connection_limiters);

}  // namespace acpp
