#pragma once

#include "acppnode/proxy/inbound.hpp"
#include "acppnode/proxy/trojan/validator.hpp"

namespace acpp {
struct StatsShard;
}  // namespace acpp

namespace acpp::proxy::trojan::inbound {

// ============================================================================
// Handler - Trojan inbound proxy handler
//
// 只负责 SHA224 认证 + 目标地址解析，不涉及 TLS（传输层由 proxyman inbound 处理）。
// ============================================================================
class Handler final : public ::acpp::Inbound {
public:
    Handler(::acpp::trojan::Validator& validator,
            ::acpp::StatsShard& stats,
            ::acpp::ConnectionLimiterPtr limiter);

    // 从已建立的传输流解析 Trojan 头（password_hash + CRLF + target + CRLF）
    ::acpp::net::awaitable<::acpp::RelayResult> Process(
        std::unique_ptr<::acpp::AsyncStream> stream,
        ::acpp::routing::Dispatcher& dispatcher,
        const ::acpp::proxyman::inbound::ReceiverSettings& receiver,
        ::acpp::net::io_context& io_context,
        ::acpp::session::Context& ctx,
        const ::acpp::TimeoutsConfig& timeouts,
        uint32_t pressure_idle_timeout) override;

private:
    ::acpp::trojan::Validator& validator_;
    ::acpp::StatsShard* stats_ = nullptr;
    ::acpp::ConnectionLimiterPtr limiter_;
};

}  // namespace acpp::proxy::trojan::inbound
