#pragma once

#include "acppnode/common/defaults.hpp"
#include "acppnode/common/target_address.hpp"
#include "acppnode/core/constants.hpp"
#include "acppnode/proxy/outbound.hpp"
#include "acppnode/transport/internet/dial_target.hpp"

#include <chrono>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace acpp {
class UDPSessionManager;

namespace app::dns {
class DNS;
}  // namespace app::dns
}  // namespace acpp

namespace acpp::freedom::outbound {

// ============================================================================
// Freedom 出站设置
// ============================================================================
struct FreedomSettings {
    std::string send_through = std::string(constants::binding::kAuto);   // auto / 0.0.0.0 / 具体 IPv4
    std::string domain_strategy = std::string(constants::protocol::kAsIs);
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

    // UDP 拨号（Full Cone NAT）：返回 Worker 的 UDPSession*（nullptr=失败）。
    net::awaitable<::acpp::UDPSession*> DialUDP(session::Context& ctx) override;

    std::string_view Tag() const noexcept override { return tag_; }

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

private:
    // 解析目标地址列表（保留多 IP 顺序，按策略过滤/排序）
    net::awaitable<std::expected<std::vector<net::ip::address>, ErrorCode>>
    ResolveTargets(session::Context& ctx);

    // 确定本地绑定地址
    std::optional<net::ip::address> DetermineLocalAddress(
        const tcp::endpoint* inbound_local_addr,
        const net::ip::address& remote_addr);

    // 取得（或创建）当前 Worker 的 Full Cone UDP socket。Process 的 UDP 数据面
    // 与 Mux 用的 DialUDP 共用同一获取逻辑；返回 nullptr 表示拨号失败。
    ::acpp::UDPSession* AcquireUdpSession(session::Context& ctx);

    std::string tag_;
    FreedomSettings settings_;
    ::acpp::app::dns::DNS& dns_service_;
    ::acpp::UDPSessionManager* udp_session_manager_;  // Per-worker UDP manager
    std::chrono::seconds dial_timeout_;
    std::optional<TargetAddress> redirect_target_;
    std::string redirect_target_text_;
    OutboundTransportTarget::BindMode bind_mode_ = OutboundTransportTarget::BindMode::None;
    DomainStrategy domain_strategy_ = DomainStrategy::AsIs;
    std::optional<net::ip::address> explicit_send_through_addr_;
    std::optional<std::string> explicit_udp_bind_addr_;
    std::optional<std::string> explicit_udp_session_id_;
    StreamSettings stream_settings_;          // 默认 tcp/none
};

}  // namespace acpp::freedom::outbound
