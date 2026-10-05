#include "acppnode/app/bootstrap_inbounds.hpp"

#include "acppnode/app/port_binding.hpp"
#include "acppnode/app/proxyman/inbound/receiver_settings.hpp"
#include "acppnode/app/rate_limiter.hpp"
#include "acppnode/runtime/runtime.hpp"

#include <format>
#include <stdexcept>
#include <utility>

namespace acpp {

net::awaitable<void> SetupRuntimeInbounds(Runtime& runtime, InboundStartup startup) {
    const auto& inbounds = startup.entries;
    ConnectionLimiterPtr connection_limiter = startup.limiter;
    co_await runtime.Initialize();

    for (const auto& inbound : inbounds) {
        const auto fail = [&](const char* stage) {
            throw std::runtime_error(std::format(
                "static inbound startup failed tag={} port={} stage={}",
                inbound.tag, inbound.port, stage));
        };
        auto receiver = proxyman::inbound::MakeReceiverSettings(
            inbound.tag,
            inbound.all_tags,
            inbound.protocol,
            inbound.stream_settings,
            inbound.sniffing,
            connection_limiter,
            ProxyProtocolMode::Auto,
            inbound.outbound_policy);

        if (!co_await runtime.RegisterInbound(
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
        if (!co_await runtime.AddListener(binding)) {
            fail("tcp-listen");
        }

        if (!co_await runtime.AddUdpListener(
                binding,
                connection_limiter,
                inbound.build_request)) {
            fail("udp-listen");
        }
    }
}


}  // namespace acpp
