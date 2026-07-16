#pragma once

#include "acppnode/core/constants.hpp"
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
    std::string response = std::string(constants::protocol::kNone);  // none / http
};

// ============================================================================
// Handler - 黑洞出站（丢弃所有连接）
// ============================================================================
class Handler final : public Outbound {
public:
    Handler(const std::string& tag, const BlackholeSettings& settings);

    net::awaitable<OutboundProcessResult> Process(
        net::io_context& io_context,
        const tcp::endpoint* inbound_local_addr,
        session::Context& ctx,
        const TimeoutsConfig& timeouts,
        transport::Link inbound,
        StatsShard& stats,
        const RelayConfig& relay_config,
        std::span<const uint8_t> initial_payload,
        buf::MultiBuffer& first_payload,
        std::chrono::seconds relay_idle_timeout,
        std::chrono::seconds relay_write_timeout) override;

    std::string_view Tag() const noexcept override { return tag_; }

private:
    std::string tag_;
    BlackholeSettings settings_;
};

}  // namespace acpp::proxy::blackhole::outbound
