#pragma once

#include "acppnode/common.hpp"

namespace acpp {

class ConnectionLimiter;

[[nodiscard]] std::vector<std::string> SetupStaticInbounds(
    const Config& config,
    std::vector<std::unique_ptr<Worker>>& workers,
    std::shared_ptr<ConnectionLimiter> connection_limiter);

void SetupTestMode(
    std::vector<std::unique_ptr<Worker>>& workers,
    std::shared_ptr<ConnectionLimiter> connection_limiter);

}  // namespace acpp
