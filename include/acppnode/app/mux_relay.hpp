#pragma once

#include "acppnode/common.hpp"
#include "acppnode/app/session_context.hpp"
#include "acppnode/transport/async_stream.hpp"
#include "acppnode/app/stats.hpp"
#include "acppnode/app/relay.hpp"

namespace acpp {

// 前向声明
class IOutbound;

// ============================================================================
// DoMuxRelay - Mux.Cool 多路复用 Relay（VMess Command=Mux）
//
// client_stream: VMessServerAsyncStream（已完成 AEAD 解密）
// outbound: 子会话共用的出站（每个子会话独立拨号）
// ============================================================================
cobalt::task<RelayResult> DoMuxRelay(
    AsyncStream& client_stream,
    IOutbound* outbound,
    SessionContext& parent_ctx,
    StatsShard& stats,
    const UDPRelayConfig& config = UDPRelayConfig{});

}  // namespace acpp
