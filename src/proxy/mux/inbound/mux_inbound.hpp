#pragma once

#include "acppnode/common/asio_types.hpp"
#include "acppnode/app/relay_types.hpp"
#include "acppnode/transport/link.hpp"

#include <cstdint>

namespace acpp {
class AsyncStream;
struct StatsShard;
struct TimeoutsConfig;
}  // namespace acpp

namespace acpp::routing {
class Dispatcher;
struct DispatchPolicy;
}  // namespace acpp::routing

namespace acpp::session {
struct Context;
}  // namespace acpp::session

namespace acpp::mux {

// ============================================================================
// ProcessInbound - Mux.Cool 多路复用入站容器（VMess/VLESS Command=Mux）
//
// 对应 xray-core common/mux server 侧职责。
//
// client_link: 已完成外层协议解密的 inbound Link。
// dispatcher: 子会话回到主请求链路重新路由和出站处理。
// ============================================================================
net::awaitable<RelayResult> ProcessInbound(
    net::io_context& io_context,
    transport::Link client_link,
    AsyncStream& client_control,
    routing::Dispatcher& dispatcher,
    const routing::DispatchPolicy& policy,
    session::Context& parent_ctx,
    StatsShard& stats,
    const TimeoutsConfig& timeouts,
    uint32_t pressure_idle_timeout);

}  // namespace acpp::mux
