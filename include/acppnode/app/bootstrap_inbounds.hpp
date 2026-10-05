#pragma once
#include "acppnode/app/static_inbound_prepared_config.hpp"
#include "acppnode/common/asio_types.hpp"
#include <vector>

namespace acpp {
class ConnectionLimiter;
class Runtime;
struct InboundStartup {
    std::vector<StaticInboundRuntimeEntry> entries;
    ConnectionLimiter* limiter = nullptr;
};
net::awaitable<void> SetupRuntimeInbounds(Runtime&, InboundStartup);
}  // namespace acpp
