#pragma once

#include "common/target_address.hpp"
#include "proxy/outbound.hpp"
#include "proxy/freedom_domain_strategy.hpp"
#include "app/proxyman/outbound/prepared_config.hpp"
#include "common/allocator.hpp"

#include <chrono>
#include <tl/expected.hpp>
#include <memory>
#include <optional>
#include <string_view>

namespace app::dns {
class DNS;
}  // namespace app::dns

namespace proxy::freedom::outbound {

// ============================================================================
// Freedom 出站设置（sendThrough 属于 Handler 的 sender settings）
// ============================================================================
struct FreedomSettings {
    DomainStrategy domain_strategy = DomainStrategy::AsIs;
    std::optional<TargetAddress> redirect;  // 重定向目标（缺省=不重定向），加载时已校验
};

[[nodiscard]] proxyman::outbound::PreparedOutboundCreator
PrepareOutbound(FreedomSettings settings);

// ============================================================================
// Handler - 直连出站
//
// domainStrategy 是协议策略（同 Xray freedom）：本协议解析并排序目标地址，
// 再经 Handler 的 OutboundDialer 拨号；原生 UDP 同样经 dialer 选择绑定地址。
// ============================================================================
class Handler final : public Outbound {
public:
    explicit Handler(const FreedomSettings& settings);

    net::awaitable<OutboundProcessResult> Process(
        session::Context& ctx,
        transport::Link inbound,
        OutboundDialer& dialer,
        const TimeoutsConfig& timeouts,
        StatsShard& stats,
        const RelayConfig& relay_config,
        buf::MultiBufferBatch first_payload,
        std::chrono::seconds relay_idle_timeout,
        std::chrono::seconds relay_write_timeout) override;

private:
    net::awaitable<tl::expected<std::unique_ptr<AsyncStream>, ErrorCode>>
    DialTarget(OutboundDialer& dialer, session::Context& ctx);

    // 解析目标地址列表（保留多 IP 顺序，按策略过滤/排序）
    net::awaitable<tl::expected<memory::ThreadLocalVector<net::ip::address>, ErrorCode>>
    ResolveTargets(::app::dns::DNS& dns, session::Context& ctx);

    DomainStrategy domain_strategy_;
    std::optional<TargetAddress> redirect_target_;
};

}  // namespace proxy::freedom::outbound
