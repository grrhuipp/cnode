#pragma once

#include "acppnode/common/asio_types.hpp"
#include "acppnode/common/error.hpp"
#include "acppnode/common/initial_payload.hpp"
#include "acppnode/app/relay_types.hpp"
#include "acppnode/app/udp_types.hpp"
#include "acppnode/transport/link.hpp"

#include <memory>

namespace acpp {

class AsyncStream;
class Outbound;

namespace proxyman::inbound {
struct ReceiverSettings;
}

namespace session {
struct Context;
}

struct StatsShard;
struct TimeoutsConfig;

namespace routing {

struct DispatchResult {
    std::shared_ptr<Outbound> handler;
    ErrorCode error = ErrorCode::OK;
};

// ============================================================================
// Dispatcher - routing feature interface
//
// Route 负责出站标签决策；Dispatch 负责接收协议层准备好的
// transport::Link / 初始 payload / relay 参数，并把连接交给
// outbound.Process 进入 relay。
// ============================================================================
class Dispatcher {
public:
    virtual ~Dispatcher() noexcept = default;

    virtual net::awaitable<RelayResult> Dispatch(
        net::io_context& io_context,
        const proxyman::inbound::ReceiverSettings& receiver,
        std::unique_ptr<AsyncStream> inbound,
        transport::Link inbound_link,
        InitialPayload first_packet,
        session::Context& ctx,
        StatsShard& stats,
        const TimeoutsConfig& timeouts) = 0;

    [[nodiscard]] virtual DispatchResult Route(
        session::Context& ctx,
        const proxyman::inbound::ReceiverSettings& receiver) const noexcept = 0;
    [[nodiscard]] virtual DispatchResult Route(session::Context& ctx) const noexcept = 0;
};

}  // namespace routing
}  // namespace acpp
