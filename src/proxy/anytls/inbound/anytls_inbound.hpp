#pragma once

#include "proxy/inbound.hpp"
#include "common/sharded_user_stats.hpp"

#include <memory>

struct StatsShard;

namespace anytls {
class PaddingScheme;
}  // namespace anytls

namespace proxy::anytls::inbound {

// ============================================================================
// Handler - AnyTLS inbound proxy
//
// AnyTLS 服务端侧协议处理器：负责 sha256(password) 认证头、
// settings/SYN/PSH/FIN 帧解析，并将单请求 TCP framed stream 交给 dispatcher。
//
// 协议核心 codec 位于 anytls；handler 与其它协议一致归于
// proxy::<name>::inbound（对应 vmess core=vmess, handler=proxy::vmess::*）。
// ============================================================================
class Handler final : public Inbound {
public:
    Handler(::UserOnlineTracker& validator,
            ::StatsShard& stats,
            ::ConnectionLimiter* limiter,
            std::shared_ptr<const ::anytls::PaddingScheme> padding_scheme = {});

    net::awaitable<RelayResult> Process(
        std::unique_ptr<AsyncStream> stream,
        routing::Dispatcher& dispatcher,
        const proxyman::inbound::ReceiverSettings& receiver,
        net::io_context& io_context,
        session::Context& ctx,
        const TimeoutsConfig& timeouts,
        uint32_t pressure_idle_timeout) override;

private:
    ::UserOnlineTracker& validator_;
    ::StatsShard* stats_ = nullptr;
    ::ConnectionLimiter* limiter_;
    std::shared_ptr<const ::anytls::PaddingScheme> padding_scheme_;
};

}  // namespace proxy::anytls::inbound
