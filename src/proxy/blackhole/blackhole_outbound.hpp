#pragma once

#include "proxy/outbound.hpp"

#include <chrono>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

namespace proxy::blackhole::outbound {

// ============================================================================
// Blackhole 出站设置
// ============================================================================
struct BlackholeSettings {
    bool http_response = false;  // response.type == "http"
};

// ============================================================================
// Handler - 黑洞出站（丢弃所有连接）
// ============================================================================
class Handler final : public Outbound {
public:
    explicit Handler(const BlackholeSettings& settings);

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
    bool http_response_;
};

}  // namespace proxy::blackhole::outbound
