#pragma once

#include "acppnode/app/relay_types.hpp"
#include "acppnode/common/asio_types.hpp"
#include "acppnode/transport/link.hpp"

#include <cstdint>

namespace acpp {
class AsyncStream;
struct StatsShard;
struct TimeoutsConfig;

namespace proxyman::inbound {
struct ReceiverSettings;
}
namespace routing {
class Dispatcher;
}
namespace session {
struct Context;
}

namespace app {

// Worker-local Mux session boundary. It owns only Mux framing and data movement;
// every decoded substream re-enters Dispatcher::Dispatch for route and outbound
// selection, rather than acquiring an outbound or router itself.
class MuxSessionHandler final {
public:
    net::awaitable<RelayResult> Process(
        net::io_context& io_context,
        transport::Link inbound_link,
        AsyncStream& inbound_control,
        routing::Dispatcher& dispatcher,
        const proxyman::inbound::ReceiverSettings& receiver,
        session::Context& parent_ctx,
        StatsShard& stats,
        const TimeoutsConfig& timeouts,
        uint32_t pressure_idle_timeout);
};

}  // namespace app
}  // namespace acpp
