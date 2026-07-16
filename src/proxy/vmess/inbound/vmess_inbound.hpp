#pragma once

#include "acppnode/proxy/inbound.hpp"
#include "../validator.hpp"

namespace acpp {
struct StatsShard;
}  // namespace acpp

namespace acpp::proxy::vmess::inbound {

// ============================================================================
// Handler - VMess inbound proxy handler
//
// 只负责 VMess AEAD 握手 + 用户认证，不涉及 TLS/WS（传输层由 proxyman inbound 处理）。
// ============================================================================
class Handler final : public ::acpp::Inbound {
public:
    Handler(::acpp::vmess::TimedUserValidator& validator,
            ::acpp::StatsShard& stats,
            ::acpp::ConnectionLimiterPtr limiter);

    // 从已建立的传输流解析 VMess AEAD 头，完成用户认证，填充 ctx
    ::acpp::net::awaitable<::acpp::RelayResult> Process(
        std::unique_ptr<::acpp::AsyncStream> stream,
        ::acpp::routing::Dispatcher& dispatcher,
        const ::acpp::proxyman::inbound::ReceiverSettings& receiver,
        ::acpp::net::io_context& io_context,
        ::acpp::session::Context& ctx,
        const ::acpp::TimeoutsConfig& timeouts) override;

private:
    ::acpp::vmess::TimedUserValidator& validator_;
    ::acpp::StatsShard* stats_ = nullptr;
    ::acpp::ConnectionLimiterPtr limiter_;
};

}  // namespace acpp::proxy::vmess::inbound
