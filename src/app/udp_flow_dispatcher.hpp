#pragma once

#include "app/relay.hpp"
#include "common/asio_types.hpp"
#include "common/error.hpp"
#include "common/multi_buffer.hpp"
#include "routing/dispatcher.hpp"
#include "transport/link.hpp"

#include <cstdint>
#include <memory>

namespace common {
struct Context;
}
namespace infra {
struct TimeoutsConfig;
}
namespace transport {
class AsyncStream;
}

namespace app {

class DefaultDispatcher;
struct StatsShard;

// Splits one authenticated UDP protocol association into independently routed
// logical flows. Protocol authentication/replay state stays with the caller;
// each child owns its sniff, route, outbound and access-log lifecycle.
class UdpFlowDispatcher final {
public:
    static net::awaitable<void> Run(
        DefaultDispatcher& dispatcher,
        net::io_context& io_context,
        const routing::DispatchPolicy& policy,
        std::unique_ptr<transport::AsyncStream> inbound,
        transport::Link inbound_link,
        common::InitialPayload first_packet,
        common::Context& parent_context,
        StatsShard& stats,
        const infra::TimeoutsConfig& timeouts,
        uint32_t pressure_idle_timeout,
        RelayResult& result,
        common::ErrorCode& cancellation_reason);
};

}  // namespace app
