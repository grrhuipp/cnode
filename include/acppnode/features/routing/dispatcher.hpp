#pragma once

#include "acppnode/common/asio_types.hpp"
#include "acppnode/common/initial_payload.hpp"
#include "acppnode/app/relay_types.hpp"
#include "acppnode/app/udp_types.hpp"
#include "acppnode/features/routing/dispatch_policy.hpp"
#include "acppnode/transport/link.hpp"

#include <memory>

namespace acpp {

class AsyncStream;

namespace session {
struct Context;
}

struct StatsShard;
struct TimeoutsConfig;

namespace routing {

// ============================================================================
// Dispatcher - routing feature interface
//
// Dispatch 接收协议层准备好的不可变策略、transport::Link、初始 payload
// 和 relay 参数；路由编排是实现细节，唯一公开热路径直接进入
// outbound.Process 和 relay。
// ============================================================================
class Dispatcher {
public:
    virtual ~Dispatcher() noexcept = default;

    virtual net::awaitable<RelayResult> Dispatch(
        net::io_context& io_context,
        const DispatchPolicy& policy,
        std::unique_ptr<AsyncStream> inbound,
        transport::Link inbound_link,
        InitialPayload first_packet,
        session::Context& ctx,
        StatsShard& stats,
        const TimeoutsConfig& timeouts) = 0;
};

}  // namespace routing
}  // namespace acpp
