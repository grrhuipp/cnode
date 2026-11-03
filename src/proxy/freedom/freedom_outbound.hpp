#pragma once

#include "acppnode/common/defaults.hpp"
#include "acppnode/common/target_address.hpp"
#include "acppnode/proxy/outbound.hpp"
#include "acppnode/transport/internet/outbound_bind.hpp"
#include "acppnode/transport/internet/stream_settings.hpp"
#include "acppnode/proxy/freedom_domain_strategy.hpp"
#include "acppnode/app/proxyman/outbound/prepared_config.hpp"
#include "acppnode/common/allocator.hpp"

#include <chrono>
#include <cstdint>
#include <tl/expected.hpp>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace acpp {
namespace app::dns {
class DNS;
}  // namespace app::dns
}  // namespace acpp

namespace acpp::proxy::freedom::outbound {

// ============================================================================
// Freedom 出站设置
// ============================================================================
struct FreedomSettings {
    OutboundBind send_through = OutboundBind::Auto();
    DomainStrategy domain_strategy = DomainStrategy::AsIs;
    std::string redirect;                 // 重定向目标 "host:port"（空=不重定向）
};

[[nodiscard]] proxyman::outbound::PreparedOutboundCreator
PrepareOutbound(FreedomSettings settings);

// ============================================================================
// Handler - 直连出站
// ============================================================================
class Handler final : public Outbound {
public:
    Handler(std::string_view tag,
            const FreedomSettings& settings,
            ::acpp::app::dns::DNS& dns_service,
            std::chrono::seconds dial_timeout = std::chrono::seconds(defaults::kDialTimeout));

    net::awaitable<OutboundProcessResult> Process(
        net::io_context& io_context,
        const tcp::endpoint* inbound_local_addr,
        session::Context& ctx,
        const TimeoutsConfig& timeouts,
        transport::Link inbound,
        StatsShard& stats,
        const RelayConfig& relay_config,
        buf::MultiBufferBatch first_payload,
        std::chrono::seconds relay_idle_timeout,
        std::chrono::seconds relay_write_timeout) override;

    std::string_view Tag() const noexcept override { return tag_; }

private:
    net::awaitable<tl::expected<std::unique_ptr<AsyncStream>, ErrorCode>>
    DialOutboundStream(net::io_context& io_context,
                       const tcp::endpoint* inbound_local_addr,
                       session::Context& ctx);

    // 解析目标地址列表（保留多 IP 顺序，按策略过滤/排序）
    net::awaitable<tl::expected<memory::ThreadLocalVector<net::ip::address>, ErrorCode>>
    ResolveTargets(session::Context& ctx);

    // 确定本地绑定地址
    std::optional<net::ip::address> DetermineLocalAddress(
        const tcp::endpoint* inbound_local_addr,
        const net::ip::address& remote_addr);

    memory::ThreadLocalString tag_;
    OutboundBind send_through_;
    DomainStrategy domain_strategy_;
    ::acpp::app::dns::DNS& dns_service_;
    std::chrono::seconds dial_timeout_;
    std::optional<TargetAddress> redirect_target_;
    StreamSettings stream_settings_;          // 默认 tcp/none
};

}  // namespace acpp::proxy::freedom::outbound
