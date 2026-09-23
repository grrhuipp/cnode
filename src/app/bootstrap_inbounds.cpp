#include "acppnode/app/bootstrap_inbounds.hpp"

#include "acppnode/app/port_binding.hpp"
#include "acppnode/app/proxyman/inbound/receiver_settings.hpp"
#include "acppnode/app/rate_limiter.hpp"
#include "acppnode/app/worker.hpp"
#include "acppnode/core/constants.hpp"

#include <format>
#include <stdexcept>
#include <utility>

namespace acpp {

namespace {

net::awaitable<void> SetupWorkerInbounds(
    Worker& worker,
    std::vector<StaticInboundRuntimeEntry> inbounds,
    ConnectionLimiterPtr connection_limiter) {
    co_await worker.StartRuntimeTask();

    for (const auto& inbound : inbounds) {
        const auto fail = [&](const char* stage) {
            throw std::runtime_error(std::format(
                "static inbound startup failed worker={} tag={} port={} stage={}",
                worker.Id(), inbound.tag, inbound.port, stage));
        };
        auto outbound_policy = [&]() -> routing::OutboundSelectionPolicy {
            if (inbound.routing_enabled) {
                return routing::RouteWithFallback(
                    std::string(constants::protocol::kDirect));
            }
            return routing::ForceOutbound(
                std::string(constants::protocol::kDirect));
        }();
        auto receiver = proxyman::inbound::MakeReceiverSettings(
            inbound.tag,
            inbound.all_tags,
            inbound.protocol,
            inbound.stream_settings,
            inbound.sniffing,
            connection_limiter,
            ProxyProtocolMode::Auto,
            std::move(outbound_policy));

        if (!co_await worker.RegisterInboundTask(
                connection_limiter,
                inbound.build_request,
                std::move(receiver))) {
            fail("register");
        }

        auto binding = MakePortBinding(
            inbound.port,
            inbound.protocol,
            inbound.tag,
            inbound.listen);
        if (!co_await worker.AddListenerTask(binding)) {
            fail("tcp-listen");
        }

        if (!co_await worker.AddUdpListenerTask(
                binding,
                connection_limiter,
                inbound.build_request)) {
            fail("udp-listen");
        }
    }
}

}  // namespace

InboundStartup QueueInboundStartup(
    const std::vector<StaticInboundRuntimeEntry>& runtime_inbounds,
    const std::vector<std::unique_ptr<Worker>>& workers,
    const std::vector<std::unique_ptr<ConnectionLimiter>>& connection_limiters) {
    InboundStartup startup;
    startup.entries = runtime_inbounds;
    startup.worker_results.reserve(workers.size());
    for (const auto& worker : workers) {
        if (worker->Id() >= connection_limiters.size()) {
            throw std::runtime_error("worker has no matching connection limiter");
        }
        auto* limiter = connection_limiters[worker->Id()].get();
        startup.worker_results.push_back(worker->PostForFuture(
            SetupWorkerInbounds(*worker, startup.entries, limiter)));
    }
    return startup;
}

}  // namespace acpp
