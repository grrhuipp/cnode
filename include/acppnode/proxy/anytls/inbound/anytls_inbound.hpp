#pragma once

#include "acppnode/proxy/inbound.hpp"

#include <string>

namespace acpp {
struct StatsShard;
}  // namespace acpp

namespace acpp::anytls {
class Validator;
}  // namespace acpp::anytls

namespace acpp::anytls::inbound {

// ============================================================================
// Handler - AnyTLS inbound proxy
//
// AnyTLS 服务端侧协议处理器：负责 sha256(password) 认证头、
// settings/SYN/PSH/FIN 帧解析，并将单请求 TCP framed stream 交给 dispatcher。
// ============================================================================
class Handler final : public Inbound {
public:
    Handler(StatsShard& stats,
            Validator& validator,
            ConnectionLimiterPtr limiter,
            std::string padding_scheme = {});

    net::awaitable<RelayResult> Process(
        std::unique_ptr<AsyncStream> stream,
        routing::Dispatcher& dispatcher,
        const proxyman::inbound::ReceiverSettings& receiver,
        net::io_context& io_context,
        session::Context& ctx,
        const TimeoutsConfig& timeouts,
        uint32_t pressure_idle_timeout) override;

    void SetBanTrackingEnabled(bool /*enabled*/) noexcept override {}

private:
    StatsShard* stats_ = nullptr;
    Validator* validator_ = nullptr;
    std::string padding_scheme_raw_;
    std::string padding_scheme_md5_;
};

}  // namespace acpp::anytls::inbound
