#pragma once

#include "acppnode/common/defaults.hpp"
#include "acppnode/common/target_address.hpp"
#include "acppnode/proxy/outbound.hpp"
#include "acppnode/transport/internet/outbound_bind.hpp"
#include "acppnode/transport/internet/stream_settings.hpp"

#include <chrono>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace acpp {
class UDPSession;
class UDPSessionManager;

namespace app::dns {
class DNS;
}  // namespace app::dns
}  // namespace acpp

namespace acpp::proxy::freedom::outbound {

enum class DomainStrategy : uint8_t {
    AsIs,
    UseIP,
    UseIPv6v4,
    UseIPv4,
    UseIPv4v6,
    UseIPv6,
    ForceIP,
    ForceIPv6v4,
    ForceIPv6,
    ForceIPv4v6,
    ForceIPv4,
};

// ============================================================================
// Freedom 出站设置
// ============================================================================
struct FreedomSettings {
    OutboundBind send_through = OutboundBind::Auto();
    DomainStrategy domain_strategy = DomainStrategy::AsIs;
    std::string redirect;                 // 重定向目标 "host:port"（空=不重定向）
    bool enable_udp = true;               // 是否启用 UDP
    int udp_timeout = defaults::kUdpSessionTimeout;     // UDP 会话超时（秒）
};

// ============================================================================
// Handler - 直连出站
// ============================================================================
class Handler final : public Outbound {
public:
    Handler(const std::string& tag,
            const FreedomSettings& settings,
            ::acpp::app::dns::DNS& dns_service,
            ::acpp::UDPSessionManager* udp_session_manager,  // Per-worker UDP manager
            std::chrono::seconds dial_timeout = std::chrono::seconds(defaults::kDialTimeout));

    net::awaitable<OutboundProcessResult> Process(
        net::io_context& io_context,
        const tcp::endpoint* inbound_local_addr,
        session::Context& ctx,
        const TimeoutsConfig& timeouts,
        transport::Link inbound,
        StatsShard& stats,
        const RelayConfig& relay_config,
        std::span<const uint8_t> initial_payload,
        buf::MultiBuffer& first_payload,
        std::chrono::seconds relay_idle_timeout,
        std::chrono::seconds relay_write_timeout) override;

    std::string_view Tag() const noexcept override { return tag_; }

private:
    // 解析目标地址列表（保留多 IP 顺序，按策略过滤/排序）
    net::awaitable<std::expected<std::vector<net::ip::address>, ErrorCode>>
    ResolveTargets(session::Context& ctx);

    // 确定本地绑定地址
    std::optional<net::ip::address> DetermineLocalAddress(
        const tcp::endpoint* inbound_local_addr,
        const net::ip::address& remote_addr);

    // 取得（或创建）当前 Worker 的 Full Cone UDP socket。仅由 Process 的
    // UDP 数据面调用；保留 manager 返回的精确容量/绑定错误。
    std::expected<::acpp::UDPSession*, ErrorCode> AcquireUdpSession(
        session::Context& ctx);

    std::string tag_;
    FreedomSettings settings_;
    ::acpp::app::dns::DNS& dns_service_;
    ::acpp::UDPSessionManager* udp_session_manager_;  // Per-worker UDP manager
    std::chrono::seconds dial_timeout_;
    std::optional<TargetAddress> redirect_target_;
    std::string redirect_target_text_;
    std::optional<std::string> explicit_udp_session_id_;
    StreamSettings stream_settings_;          // 默认 tcp/none
};

}  // namespace acpp::proxy::freedom::outbound
