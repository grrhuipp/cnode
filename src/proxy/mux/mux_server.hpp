#pragma once

#include "app/relay.hpp"
#include "common/asio_types.hpp"
#include "transport/link.hpp"

#include <cstdint>

namespace transport {

class AsyncStream;

}  // namespace transport
namespace app {

struct StatsShard;
struct AdmissionEnvironment;

}  // namespace app
namespace infra {

struct TimeoutsConfig;

}  // namespace infra


namespace routing {
class Dispatcher;
struct DispatchPolicy;
}  // namespace routing

namespace common {
struct Context;
}  // namespace common

namespace proxy {

// ============================================================================
// ServeMuxInbound - Mux.Cool 多路复用入站服务端（VMess/VLESS Command=Mux）
//
// 对应 xray-core common/mux server 侧职责；帧编解码在 common/mux/mux_codec.hpp。
//
// client_link: 已完成外层协议解密的 inbound Link。
// dispatcher: 子会话回到主请求链路重新路由和出站处理。
// environment: each child takes logical admission under the physical family;
// a refused child closes with OptionError without affecting its parent.
// ============================================================================
net::awaitable<app::RelayResult> ServeMuxInbound(
    net::io_context& io_context,
    transport::Link client_link,
    transport::AsyncStream& client_control,
    routing::Dispatcher& dispatcher,
    const routing::DispatchPolicy& policy,
    const app::AdmissionEnvironment& environment,
    common::Context& parent_ctx,
    app::StatsShard& stats,
    const infra::TimeoutsConfig& timeouts,
    uint32_t pressure_idle_timeout);

}  // namespace proxy
