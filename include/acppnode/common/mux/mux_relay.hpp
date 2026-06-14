#pragma once

#include "acppnode/common/asio_types.hpp"
#include "acppnode/app/relay_types.hpp"
#include "acppnode/app/udp_types.hpp"

namespace acpp {
class AsyncStream;
}  // namespace acpp

namespace acpp::features::outbound {
class Handler;
}  // namespace acpp::features::outbound

namespace acpp::session {
struct Context;
}  // namespace acpp::session

namespace acpp::mux {

// ============================================================================
// DoMuxRelay - Mux.Cool 多路复用 Relay（VMess Command=Mux）
//
// 对应 xray-core common/mux server 侧职责。
//
// client_stream: VMess inbound Link（已完成 AEAD 解密）
// outbound_handler: 子会话共用的出站 feature Handler（每个子会话独立拨号）
// ============================================================================
net::awaitable<RelayResult> DoMuxRelay(
    net::io_context& io_context,
    AsyncStream& client_stream,
    ::acpp::features::outbound::Handler& outbound_handler,
    session::Context& parent_ctx,
    const UDPRelayConfig& config = UDPRelayConfig{});

}  // namespace acpp::mux
