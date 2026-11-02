#pragma once

#include "acppnode/app/static_inbound_prepared_config.hpp"

#include "acppnode/common/asio_types.hpp"
#include <memory>
#include <vector>

namespace acpp {

class Worker;
struct InboundStartup {
    std::vector<StaticInboundRuntimeEntry> entries;
};

net::awaitable<void> StartWorkerInbounds(
    Worker& worker, std::vector<StaticInboundRuntimeEntry> inbounds);

}  // namespace acpp
