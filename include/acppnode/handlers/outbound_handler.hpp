#pragma once

#include "acppnode/common.hpp"
#include "acppnode/common/error.hpp"
#include "acppnode/app/session_context.hpp"
#include "acppnode/transport/async_stream.hpp"

#include <expected>
#include <span>
#include <vector>
#include <memory>

namespace acpp {

using OutboundHandshakeResult = std::expected<void, ErrorCode>;
using OutboundWrapResult = std::expected<std::unique_ptr<AsyncStream>, ErrorCode>;

// ============================================================================
// IOutboundHandler - 出站协议处理器接口（代理层）
//
// 职责：纯协议编码 + 握手，不涉及传输层（TLS/WS 由 SessionHandler 负责）。
//
// 调用顺序（由 SessionHandler 保证）：
//   1. Handshake(stream, ctx, initial_payload)  → 发送协议头（可选读响应）
//   2. WrapStream(stream, ctx)                  → 加密/帧装饰后的流
//
// 协议实现示例：
//   - VMessOutboundHandler: Handshake 是 noop，WrapStream 内发送 AEAD 请求头
//   - FreedomOutboundHandler: Handshake 是 noop，WrapStream 透传原流
//   - TrojanOutboundHandler: Handshake 发送 SHA224+目标，WrapStream 透传原流
// ============================================================================
class IOutboundHandler {
public:
    virtual ~IOutboundHandler() noexcept = default;

    // -----------------------------------------------------------------------
    // 向出站服务器发送协议握手头
    //
    // @param stream           已完成传输层握手的字节流
    // @param ctx              会话上下文（含目标地址、用户信息等）
    // @param initial_payload  入站解析时得到的首个应用层数据（可能为空）
    //                         Freedom 等出站需要先发此数据
    // @return                 success: void；failure: ErrorCode
    // -----------------------------------------------------------------------
    virtual cobalt::task<OutboundHandshakeResult> Handshake(
        AsyncStream& stream,
        const SessionContext& ctx,
        std::span<const uint8_t> initial_payload) = 0;

    // -----------------------------------------------------------------------
    // 包装流以应用出站协议加密/帧格式
    //
    // @param stream  Handshake 使用过的同一流（ownership 转移）
    // @param ctx     会话上下文
    // @return        success: wrapped stream；failure: ErrorCode
    // -----------------------------------------------------------------------
    virtual cobalt::task<OutboundWrapResult> WrapStream(
        std::unique_ptr<AsyncStream> stream,
        const SessionContext& ctx) = 0;
};

}  // namespace acpp
