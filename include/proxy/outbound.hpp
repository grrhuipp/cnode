#pragma once

#include "common/allocator.hpp"
#include "common/asio_types.hpp"
#include "common/error.hpp"
#include "common/buf/multi_buffer_batch.hpp"
#include "app/relay_types.hpp"
#include "transport/link.hpp"

#include <chrono>
#include <tl/expected.hpp>


struct StatsShard;
struct TimeoutsConfig;
class OutboundDialer;

namespace session {
struct Context;
}

using OutboundProcessResult = tl::expected<RelayResult, ErrorCode>;

// ============================================================================
// Outbound - Xray proxy.Outbound
//
// One protocol instance owned by its proxyman outbound Handler, which calls
// Process exactly once per request: the only dynamic dispatch between the
// dispatcher and the protocol. Every connection leaves through |dialer| (the
// Handler's internet.Dialer); first_payload transfers ownership and all
// application bytes enter relay.
// ============================================================================
class Outbound : public memory::ThreadAllocated {
public:
    virtual ~Outbound() noexcept = default;

    virtual net::awaitable<OutboundProcessResult> Process(
        session::Context& ctx,
        transport::Link inbound,
        OutboundDialer& dialer,
        const TimeoutsConfig& timeouts,
        StatsShard& stats,
        const RelayConfig& relay_config,
        buf::MultiBufferBatch first_payload,
        std::chrono::seconds relay_idle_timeout,
        std::chrono::seconds relay_write_timeout) = 0;
};

