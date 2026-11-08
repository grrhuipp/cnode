#pragma once

#include "app/prepared_inbound.hpp"

#include "common/asio_types.hpp"
#include <memory>
#include <vector>


class Worker;
struct InboundStartup {
    std::vector<PreparedInbound> entries;
};

net::awaitable<void> StartWorkerInbounds(
    Worker& worker, std::vector<PreparedInbound> inbounds);

