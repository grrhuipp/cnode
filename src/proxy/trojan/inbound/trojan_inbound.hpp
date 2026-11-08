#pragma once

#include "proxy/inbound.hpp"
#include "common/sharded_user_stats.hpp"

struct StatsShard;

namespace proxy::trojan::inbound {

// ============================================================================
// Handler - Trojan inbound proxy handler
//
// 只负责 SHA224 认证 + 目标地址解析，不涉及 TLS（传输层由 proxyman inbound 处理）。
// ============================================================================
class Handler final : public ::Inbound {
public:
    Handler(::UserOnlineTracker& validator,
            ::StatsShard& stats,
            ::ConnectionLimiter* limiter);

    // 从已建立的传输流解析 Trojan 头（password_hash + CRLF + target + CRLF）
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
    ::StatsShard* stats_ = nullptr;
    ::ConnectionLimiter* limiter_;
};

}  // namespace proxy::trojan::inbound
