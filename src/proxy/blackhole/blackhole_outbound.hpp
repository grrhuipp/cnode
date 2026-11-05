#pragma once

#include "acppnode/proxy/outbound.hpp"

#include <chrono>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

namespace acpp::proxy::blackhole::outbound {

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
    Handler(std::string_view tag, const BlackholeSettings& settings);

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
    memory::ThreadLocalString tag_;
    bool http_response_;
};

}  // namespace acpp::proxy::blackhole::outbound
