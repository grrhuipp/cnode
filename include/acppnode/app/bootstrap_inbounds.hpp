#pragma once

#include "acppnode/app/static_inbound_prepared_config.hpp"

#include <future>
#include <memory>
#include <string>
#include <vector>

namespace acpp {

class ConnectionLimiter;
class Worker;
struct InboundStartup {
    std::vector<StaticInboundRuntimeEntry> entries;
    std::vector<std::string> tags;
    std::vector<std::future<bool>> worker_results;
};

[[nodiscard]] InboundStartup QueueInboundStartup(
    const std::vector<StaticInboundRuntimeEntry>& runtime_inbounds,
    std::vector<std::unique_ptr<Worker>>& workers,
    const std::vector<std::unique_ptr<ConnectionLimiter>>& connection_limiters,
    bool enable_test_mode);

}  // namespace acpp
