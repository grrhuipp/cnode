#pragma once

#include "proxy/inbound.hpp"
#include "common/sharded_user_stats.hpp"

struct StatsShard;

namespace proxy::vmess::inbound {

// ============================================================================
// Handler - VMess inbound proxy handler
//
// 只负责 VMess AEAD 握手 + 用户认证，不涉及 TLS/WS（传输层由 proxyman inbound 处理）。
// ============================================================================
class Handler final : public ::Inbound {
public:
    Handler(::UserOnlineTracker& validator,
            ::StatsShard& stats,
            ::ConnectionLimiter* limiter);

    // 从已建立的传输流解析 VMess AEAD 头，完成用户认证，填充 ctx
    ::net::awaitable<::RelayResult> Process(
        std::unique_ptr<::AsyncStream> stream,
        ::routing::Dispatcher& dispatcher,
        const ::proxyman::inbound::ReceiverSettings& receiver,
        ::net::io_context& io_context,
        ::session::Context& ctx,
        const ::TimeoutsConfig& timeouts,
        uint32_t pressure_idle_timeout) override;

private:
    ::UserOnlineTracker& validator_;
    ::StatsShard& stats_;
    ::ConnectionLimiter* limiter_;
};

}  // namespace proxy::vmess::inbound
