#pragma once

#include "acppnode/common/asio_types.hpp"
#include "acppnode/common/error.hpp"
#include "acppnode/app/relay_types.hpp"
#include "acppnode/transport/link.hpp"

#include <chrono>
#include <expected>
#include <string>
#include <string_view>

namespace acpp {

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

    // 获取出站标识
    [[nodiscard]] virtual std::string_view Tag() const noexcept = 0;

    // xray-core style outbound entry. The outbound implementation owns
    // transport target resolution, dialing, protocol setup, and relay.
    // first_payload transfers ownership; all application bytes enter relay.
    virtual net::awaitable<OutboundProcessResult> Process(
        net::io_context& io_context,
        const tcp::endpoint* inbound_local_addr,
        session::Context& ctx,
        const TimeoutsConfig& timeouts,
        transport::Link inbound,
        StatsShard& stats,
        const RelayConfig& relay_config,
        buf::MultiBuffer first_payload,
        std::chrono::seconds relay_idle_timeout,
        std::chrono::seconds relay_write_timeout) = 0;
};

}  // namespace acpp
