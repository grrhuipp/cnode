#pragma once

#include "acppnode/handlers/inbound_handler.hpp"
#include "acppnode/protocol/trojan/trojan_protocol.hpp"

#include <functional>

namespace acpp {

// ============================================================================
// TrojanInboundHandler - Trojan 协议解析器（代理层，实现 IInboundHandler）
//
// 只负责 SHA224 认证 + 目标地址解析，不涉及 TLS（传输层由 SessionHandler 处理）。
// ============================================================================
class TrojanInboundHandler final : public InboundHandlerBase {
public:
    TrojanInboundHandler(trojan::TrojanUserManager& user_manager,
                         StatsShard& stats,
                         ConnectionLimiterPtr limiter,
                         std::function<void(const std::string&)> auth_callback = {});

    // 从已建立的传输流解析 Trojan 头（password_hash + CRLF + target + CRLF）
    cobalt::task<std::expected<ParsedAction, ErrorCode>> ParseStream(
        AsyncStream& stream, SessionContext& ctx) override;

    // Trojan 无加密层，直接透传原流
    cobalt::task<InboundWrapResult> WrapStream(
        std::unique_ptr<AsyncStream> stream, SessionContext& ctx) override;

private:
    trojan::TrojanUserManager& user_manager_;
    std::function<void(const std::string&)> auth_callback_;
};

// ============================================================================
// 工厂函数
// ============================================================================
[[nodiscard]] std::unique_ptr<IInboundHandler> CreateTrojanInboundHandler(
    trojan::TrojanUserManager& user_manager,
    StatsShard& stats,
    ConnectionLimiterPtr limiter,
    std::function<void(const std::string&)> auth_callback = {});

}  // namespace acpp
