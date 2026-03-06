#pragma once

#include "acppnode/handlers/inbound_handler.hpp"
#include "acppnode/protocol/vmess/vmess_protocol.hpp"

#include <functional>

namespace acpp {

// ============================================================================
// VMessInboundHandler - VMess 协议解析器（代理层，实现 IInboundHandler）
//
// 只负责 VMess AEAD 握手 + 用户认证，不涉及 TLS/WS（传输层由 SessionHandler 处理）。
// ============================================================================
class VMessInboundHandler final : public InboundHandlerBase {
public:
    VMessInboundHandler(vmess::VMessUserManager& user_manager,
                        StatsShard& stats,
                        ConnectionLimiterPtr limiter,
                        std::function<void(const std::string&)> auth_callback = {});

    // 从已建立的传输流解析 VMess AEAD 头，完成用户认证，填充 ctx
    cobalt::task<std::expected<ParsedAction, ErrorCode>> ParseStream(
        AsyncStream& stream, SessionContext& ctx) override;

    // 用 VMessServerAsyncStream 包装入站流（启用 chunk 加密）
    cobalt::task<InboundWrapResult> WrapStream(
        std::unique_ptr<AsyncStream> stream, SessionContext& ctx) override;

private:
    vmess::VMessUserManager& user_manager_;
    std::function<void(const std::string&)> auth_callback_;
};

// ============================================================================
// 工厂函数
// ============================================================================
[[nodiscard]] std::unique_ptr<IInboundHandler> CreateVMessInboundHandler(
    vmess::VMessUserManager& user_manager,
    StatsShard& stats,
    ConnectionLimiterPtr limiter,
    std::function<void(const std::string&)> auth_callback = {});

}  // namespace acpp
