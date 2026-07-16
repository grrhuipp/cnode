#pragma once

#include "acppnode/common/asio_types.hpp"
#include "acppnode/app/relay_types.hpp"
#include "acppnode/app/udp_types.hpp"
#include "acppnode/transport/link.hpp"

namespace acpp {
class AsyncStream;
struct StatsShard;
struct TimeoutsConfig;
}  // namespace acpp

namespace acpp::proxyman::inbound {
struct ReceiverSettings;
}  // namespace acpp::proxyman::inbound

namespace acpp::routing {
class Dispatcher;
}  // namespace acpp::routing

namespace acpp::session {
struct Context;
}  // namespace acpp::session

namespace acpp::mux {

// ============================================================================
// DoMuxRelay - Mux.Cool 多路复用 Relay（VMess Command=Mux）
//
// 对应 xray-core common/mux server 侧职责。
//
// client_link: VMess inbound Link（已完成 AEAD 解密）
// dispatcher: 子会话回到主请求链路重新路由和出站处理。
// ============================================================================
net::awaitable<RelayResult> DoMuxRelay(
    net::io_context& io_context,
    transport::Link client_link,
    AsyncStream& client_control,
    routing::Dispatcher& dispatcher,
    const proxyman::inbound::ReceiverSettings& receiver,
    session::Context& parent_ctx,
    StatsShard& stats,
    const TimeoutsConfig& timeouts,
    uint32_t pressure_idle_timeout,
    const UDPRelayConfig& config = UDPRelayConfig{});

}  // namespace acpp::mux
