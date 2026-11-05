#include "acppnode/app/bootstrap_inbounds.hpp"

#include "acppnode/app/port_binding.hpp"
#include "acppnode/app/proxyman/inbound/receiver_settings.hpp"
#include "acppnode/app/worker.hpp"

#include <format>
#include <stdexcept>
#include <utility>

namespace acpp {

net::awaitable<void> StartWorkerInbounds(
    Worker& worker,
    std::vector<StaticInboundRuntimeEntry> inbounds) {
    worker.StartRuntime();

    for (const auto& inbound : inbounds) {
        const auto fail = [&](const char* stage) {
            throw std::runtime_error(std::format(
                "static inbound startup failed worker={} tag={} port={} stage={}",
                worker.Id(), inbound.tag, inbound.port, stage));
        };
        auto receiver = proxyman::inbound::MakeReceiverSettings(
            inbound.tag,
            inbound.all_tags,
            inbound.protocol,
            inbound.stream_settings,
            inbound.sniffing,
            inbound.proxy_protocol,
            inbound.outbound_policy,
            {});

        if (!worker.RegisterInbound(
                inbound.build_request,
                std::move(receiver))) {
            fail("register");
        }

        auto binding = PortBinding{.port = inbound.port, .protocol = inbound.protocol, .tag = inbound.tag, .listen = inbound.listen};
        if (!worker.AddListener(binding)) {
            fail("tcp-listen");
        }

        if (!co_await worker.AddUdpListenerTask(
                binding,
                inbound.build_request)) {
            fail("udp-listen");
        }
    }
}


}  // namespace acpp
