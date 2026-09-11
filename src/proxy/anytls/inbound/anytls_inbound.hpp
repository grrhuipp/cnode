#pragma once

#include "acppnode/proxy/inbound.hpp"

#include <memory>

namespace acpp {
struct StatsShard;
}  // namespace acpp

namespace acpp::anytls {
class Validator;
class PaddingScheme;
}  // namespace acpp::anytls

namespace acpp::proxy::anytls::inbound {

// ============================================================================
// Handler - AnyTLS inbound proxy
//
// AnyTLS 服务端侧协议处理器：负责 sha256(password) 认证头、
// settings/SYN/PSH/FIN 帧解析，并将单请求 TCP framed stream 交给 dispatcher。
//
// 协议核心（codec/validator）位于 acpp::anytls；handler 与其它协议一致归于
// acpp::proxy::<name>::inbound（对应 vmess core=acpp::vmess, handler=acpp::proxy::vmess::*）。
// ============================================================================
class Handler final : public Inbound {
public:
    Handler(::acpp::anytls::Validator& validator,
            ::acpp::StatsShard& stats,
            ::acpp::ConnectionLimiterPtr limiter,
            std::shared_ptr<const ::acpp::anytls::PaddingScheme> padding_scheme = {});

    net::awaitable<RelayResult> Process(
        std::unique_ptr<AsyncStream> stream,
        routing::Dispatcher& dispatcher,
        const proxyman::inbound::ReceiverSettings& receiver,
        net::io_context& io_context,
        session::Context& ctx,
        const TimeoutsConfig& timeouts,
        uint32_t pressure_idle_timeout) override;

private:
    ::acpp::anytls::Validator& validator_;
    ::acpp::StatsShard* stats_ = nullptr;
    ::acpp::ConnectionLimiterPtr limiter_;
    std::shared_ptr<const ::acpp::anytls::PaddingScheme> padding_scheme_;
};

}  // namespace acpp::proxy::anytls::inbound
