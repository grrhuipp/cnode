#include "app/bootstrap_inbounds.hpp"

#include "app/runtime_publication.hpp"
#include "app/worker.hpp"

#include <format>
#include <stdexcept>


net::awaitable<void> StartWorkerInbounds(
    Worker& worker,
    std::vector<PreparedInbound> inbounds) {
    worker.StartRuntime();

    for (const auto& inbound : inbounds) {
        const auto failure = co_await InstallInbound(worker, inbound);
        if (failure != InboundInstallFailure::None) {
            throw std::runtime_error(std::format(
                "static inbound startup failed worker={} tag={} port={} stage={}",
                worker.Id(), inbound.binding.tag, inbound.binding.port,
                InboundInstallFailureName(failure)));
        }
    }
}

