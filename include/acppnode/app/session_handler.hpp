#pragma once

#include "acppnode/common.hpp"
#include "acppnode/app/connection_guard.hpp"
#include "acppnode/app/session_context.hpp"
#include "acppnode/app/stats.hpp"
#include "acppnode/infra/config.hpp"
#include "acppnode/protocol/sniff_config.hpp"
#include "acppnode/transport/async_stream.hpp"
#include "acppnode/transport/stream_settings.hpp"
#include "acppnode/transport/transport_stack.hpp"
#include "acppnode/handlers/inbound_handler.hpp"
#include "acppnode/handlers/outbound_handler.hpp"
#include "acppnode/protocol/outbound.hpp"
#include "acppnode/router/router.hpp"
#include "acppnode/dns/dns_service.hpp"
#include "acppnode/app/relay.hpp"

#include <optional>

namespace acpp {

// ============================================================================
// SessionContext - 入站监听器配置（SessionHandler 的调用参数）
// ============================================================================
struct ListenerContext {
    std::string      inbound_tag;             // 主标签（map key）
    std::vector<std::string> inbound_tags;   // 所有标签（路由匹配任一）
    std::string      protocol;          // "vmess" / "trojan" 等协议名
    StreamSettings   stream_settings;  // 传输层配置（network/security）
    SniffConfig      sniff_config;
    bool             proxy_protocol = true;   // 是否接受 PROXY Protocol 头（负载均衡透传真实 IP）
    std::string      fixed_outbound;          // 非空时跳过路由，直接使用该出站
    // shared_ptr 明确表达 ListenerContext 共享 handler 所有权，
    // 避免裸指针悬空风险（Worker 同时在 inbound_handlers_ 持有同一 handler）
    std::shared_ptr<IInboundHandler> inbound_handler;
    ConnectionLimiterPtr             limiter;         // 早期 IP ban 检查（TLS 握手前）
};

// ============================================================================
// SessionHandler - 应用层会话协调器
//
// 对协议一无所知：通过 IInboundHandler/IOutboundHandler vtable 调用。
//
// 完整流程：
//   1. BuildInbound    - 构建传输层堆栈（TLS→WS）
//   2. ParseStream     - 协议解析（用户认证 + 目标地址）
//   3. Sniff           - 流量嗅探（可选）
//   4. Route           - 路由决策
//   5. DNS + Dial      - 解析目标地址并拨号
//   6. BuildOutbound   - 构建出站传输层堆栈
//   7. Handshake       - 出站协议握手
//   8. WrapStream ×2   - 入站/出站流加密包装
//   9. DoRelay         - 双向数据转发
// ============================================================================
class SessionHandler {
public:
    SessionHandler(
        OutboundManager& outbound_manager,
        Router& router,
        IDnsService& dns,
        StatsShard& stats,
        const TimeoutsConfig& timeouts);

    // 处理一个已接受的原始连接
    cobalt::task<void> Handle(
        std::unique_ptr<AsyncStream> raw_conn,
        SessionContext& ctx,
        const ListenerContext& listener,
        std::optional<ConnectionLimitGuard> connection_limit = std::nullopt);

private:
    // 嗅探：尝试识别协议（不消耗数据，仅窥探）
    cobalt::task<void> DoSniff(
        AsyncStream& stream,
        SessionContext& ctx,
        const SniffConfig& sniff_cfg);

    OutboundManager& outbound_manager_;
    Router&           router_;
    IDnsService&      dns_;
    StatsShard&       stats_;
    const TimeoutsConfig& timeouts_;
};

}  // namespace acpp
