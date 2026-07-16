#pragma once

#include "acppnode/common/asio_types.hpp"
#include "acppnode/common/error.hpp"
#include "acppnode/app/relay_types.hpp"
#include "acppnode/app/rate_limiter_fwd.hpp"

#include <memory>
#include <cstdint>

namespace acpp {

class AsyncStream;
struct TimeoutsConfig;

namespace session {
struct Context;
}

namespace proxyman::inbound {
struct ReceiverSettings;
}

namespace routing {
class Dispatcher;
}

// ============================================================================
// Inbound - 入站协议处理器接口（代理层）
//
// 职责：协议解析、认证和 dispatcher handoff，不涉及传输层（TLS/WS 由 proxyman inbound 负责）。
//
// 协议实现示例：
//   - VMessInbound: Process 解析 AEAD 头后提交 session::Context 给 dispatcher
//   - TrojanInbound: Process 解析 SHA224+目标后提交 session::Context 给 dispatcher
// ============================================================================
class Inbound {
public:
    virtual ~Inbound() noexcept = default;

    // -----------------------------------------------------------------------
    // 从已建立的传输流中解析协议头，并移交给 dispatcher。
    //
    // @param stream  已完成 TLS/WS 等传输层握手的字节流
    // @param ctx     会话上下文（用于填充用户信息、错误记录）
    // @return        dispatcher/relay 结果；协议解析失败在进入 dispatcher 前返回错误
    // -----------------------------------------------------------------------
    virtual net::awaitable<RelayResult> Process(
        std::unique_ptr<AsyncStream> stream,
        routing::Dispatcher& dispatcher,
        const proxyman::inbound::ReceiverSettings& receiver,
        net::io_context& io_context,
        session::Context& ctx,
        const TimeoutsConfig& timeouts,
        uint32_t pressure_idle_timeout) = 0;
};

}  // namespace acpp
