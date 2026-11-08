#pragma once

#include "common/asio_types.hpp"
#include "app/relay_types.hpp"
#include "transport/link.hpp"

#include <cstdint>

class AsyncStream;
class ConnectionLimiter;
struct StatsShard;
struct TimeoutsConfig;

namespace routing {
class Dispatcher;
struct DispatchPolicy;
}  // namespace routing

namespace session {
struct Context;
}  // namespace session

namespace mux {

// ============================================================================
// ProcessInbound - Mux.Cool 多路复用入站容器（VMess/VLESS Command=Mux）
//
// 对应 xray-core common/mux server 侧职责。
//
// client_link: 已完成外层协议解密的 inbound Link。
// dispatcher: 子会话回到主请求链路重新路由和出站处理。
// limiter: 每个子会话按物理连接 family 取逻辑准入（与 HTTP/2 逻辑流一致），
//          被拒子会话仅以带 OptionError 的 END 关闭，不影响父连接。
// ============================================================================
net::awaitable<RelayResult> ProcessInbound(
    net::io_context& io_context,
    transport::Link client_link,
    AsyncStream& client_control,
    routing::Dispatcher& dispatcher,
    const routing::DispatchPolicy& policy,
    ConnectionLimiter* limiter,
    session::Context& parent_ctx,
    StatsShard& stats,
    const TimeoutsConfig& timeouts,
    uint32_t pressure_idle_timeout);

}  // namespace mux
