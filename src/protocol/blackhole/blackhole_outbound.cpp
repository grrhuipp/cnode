#include "acppnode/protocol/blackhole/blackhole_outbound.hpp"
#include "acppnode/protocol/protocol_registry.hpp"
#include "acppnode/infra/log.hpp"

namespace acpp {

// ============================================================================
// BlackholeOutbound 实现
// ============================================================================

BlackholeOutbound::BlackholeOutbound(const std::string& tag, 
                                     const BlackholeSettings& settings)
    : tag_(tag)
    , settings_(settings) {
}

cobalt::task<std::expected<OutboundTransportTarget, ErrorCode>>
BlackholeOutbound::ResolveTransportTarget(SessionContext& ctx) {
    // 黑洞出站直接拒绝连接
    LOG_CONN_DEBUG(ctx, "[Blackhole][{}] dropping connection to {}", tag_, ctx.target.ToString());
    co_return std::unexpected(ErrorCode::BLOCKED);
}

// ============================================================================
// 工厂函数
// ============================================================================

std::unique_ptr<IOutbound> CreateBlackholeOutbound(
    const std::string& tag,
    const BlackholeSettings& settings) {
    return std::make_unique<BlackholeOutbound>(tag, settings);
}

}  // namespace acpp

// ============================================================================
// 自注册（静态初始化，Xray init() 设计）
// ============================================================================
namespace {
const bool kBlackholeRegistered = (acpp::OutboundFactory::Instance().Register(
    "blackhole",
    [](const acpp::OutboundConfig& cfg,
       acpp::net::any_io_executor /*executor*/,
       acpp::IDnsService* /*dns*/,
       acpp::UDPSessionManager* /*udp_mgr*/,
       std::chrono::seconds /*dial_timeout*/) -> std::unique_ptr<acpp::IOutbound> {
        acpp::BlackholeSettings settings;
        if (const auto* p = cfg.settings.if_contains("response")) {
            // Xray 格式: {"response": {"type": "http"}}
            if (p->is_object()) {
                const auto& resp = p->as_object();
                if (auto* tp = resp.if_contains("type"); tp && tp->is_string()) {
                    settings.response = std::string(tp->as_string());
                }
            }
            // 兼容旧格式: {"response": "http"}
            else if (p->is_string()) {
                settings.response = std::string(p->as_string());
            }
        }
        return std::make_unique<acpp::BlackholeOutbound>(cfg.tag, settings);
    }), true);
}  // namespace
