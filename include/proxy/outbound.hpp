#pragma once

#include "common/asio_types.hpp"
#include "app/relay.hpp"
#include "common/error.hpp"
#include "common/multi_buffer.hpp"
#include "transport/link.hpp"

#include <chrono>
#include <tl/expected.hpp>


namespace app {

struct StatsShard;

}  // namespace app
namespace infra {

struct TimeoutsConfig;

}  // namespace infra
namespace transport {

class OutboundDialer;

}  // namespace transport

namespace common {
struct Context;
}

namespace proxy {

using OutboundProcessResult = tl::expected<app::RelayResult, common::ErrorCode>;

// ============================================================================
// Outbound - Xray proxy.Outbound
//
// One protocol instance owned by its proxyman outbound Handler, which calls
// Process exactly once per request: the only dynamic dispatch between the
// dispatcher and the protocol. Every connection leaves through |dialer| (the
// Handler's internet.Dialer); first_payload transfers ownership and all
// application bytes enter relay.
// ============================================================================
class Outbound {
public:
    virtual ~Outbound() noexcept = default;

    virtual net::awaitable<OutboundProcessResult> Process(
        common::Context& ctx,
        transport::Link inbound,
        transport::OutboundDialer& dialer,
        const infra::TimeoutsConfig& timeouts,
        app::StatsShard& stats,
        const app::RelayConfig& relay_config,
        common::MultiBufferBatch first_payload) = 0;
};

}  // namespace proxy

