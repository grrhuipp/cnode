#pragma once

#include <memory>
#include <string>
#include <vector>

namespace acpp {

class ConnectionLimiter;
class Worker;
struct StaticInboundRuntimeEntry;

[[nodiscard]] std::vector<std::string> SetupStaticInbounds(
    const std::vector<StaticInboundRuntimeEntry>& runtime_inbounds,
    std::vector<std::unique_ptr<Worker>>& workers,
    const std::vector<std::unique_ptr<ConnectionLimiter>>& connection_limiters);

void SetupTestMode(
    std::vector<std::unique_ptr<Worker>>& workers,
    const std::vector<std::unique_ptr<ConnectionLimiter>>& connection_limiters);

}  // namespace acpp
