#pragma once

#include "acppnode/app/prepared_inbound.hpp"

#include "acppnode/common/asio_types.hpp"
#include <memory>
#include <vector>

namespace acpp {

class Worker;
struct InboundStartup {
    std::vector<PreparedInbound> entries;
};

net::awaitable<void> StartWorkerInbounds(
    Worker& worker, std::vector<PreparedInbound> inbounds);

}  // namespace acpp
