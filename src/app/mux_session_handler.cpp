#include "acppnode/app/mux_session_handler.hpp"

#include "acppnode/common/mux/mux_relay.hpp"
#include "acppnode/common/session.hpp"
#include "acppnode/infra/config_types.hpp"
#include "acppnode/transport/async_stream.hpp"

#include <algorithm>

namespace acpp::app {

net::awaitable<RelayResult> MuxSessionHandler::Process(
    net::io_context& io_context,
    transport::Link inbound_link,
    AsyncStream& inbound_control,
    routing::Dispatcher& dispatcher,
    const proxyman::inbound::ReceiverSettings& receiver,
    session::Context& parent_ctx,
    StatsShard& stats,
    const TimeoutsConfig& timeouts,
    uint32_t pressure_idle_timeout) {
    auto relay_idle_timeout = timeouts.StreamIdleTimeout();
    if (pressure_idle_timeout > 0) {
        relay_idle_timeout = std::min(
            relay_idle_timeout, std::chrono::seconds(pressure_idle_timeout));
    }
    inbound_control.SetIdleTimeout(relay_idle_timeout);
    inbound_control.SetReadTimeout(std::chrono::seconds(0));
    inbound_control.SetWriteTimeout(
        std::min(timeouts.WriteTimeout(), relay_idle_timeout));

    UDPRelayConfig mux_config;
    mux_config.speed_limit = parent_ctx.content.speed_limit;
    co_return co_await mux::DoMuxRelay(
        io_context,
        inbound_link,
        inbound_control,
        dispatcher,
        receiver,
        parent_ctx,
        stats,
        timeouts,
        pressure_idle_timeout,
        mux_config);
}

}  // namespace acpp::app
