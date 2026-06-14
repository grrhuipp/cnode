#pragma once

#include "acppnode/common/asio_types.hpp"
#include "acppnode/common/error.hpp"
#include "acppnode/app/relay_types.hpp"
#include "acppnode/transport/link.hpp"

#include <chrono>
#include <expected>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

namespace acpp {

class UDPSession;
struct StatsShard;
struct TimeoutsConfig;

namespace buf {
class MultiBuffer;
}

namespace session {
struct Context;
}

using OutboundProcessResult = std::expected<RelayResult, ErrorCode>;

// ============================================================================
// Outbound - 出站接口
// ============================================================================
class Outbound {
public:
    virtual ~Outbound() noexcept = default;

    // UDP 拨号（Full Cone）：返回当前 Worker 的 UDPSession*（nullptr=不支持/失败）。
    // 仅服务 datagram 入站（原生 SS UDP 监听、Mux UDP 子会话）；UDP-over-TCP 隧道
    // 走 Process。出站实现只使用 Worker 私有资源，不接收 executor。
    virtual net::awaitable<UDPSession*> DialUDP(session::Context& ctx) {
        co_return nullptr;
    }

    // 获取出站标识
    [[nodiscard]] virtual std::string_view Tag() const noexcept = 0;

    // xray-core style outbound entry. The outbound implementation owns
    // transport target resolution, dialing, protocol setup, and relay.
    virtual net::awaitable<OutboundProcessResult> Process(
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
        std::chrono::seconds relay_write_timeout) = 0;
};

}  // namespace acpp
