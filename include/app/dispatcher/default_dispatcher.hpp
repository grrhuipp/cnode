#pragma once

#include "features/routing/dispatcher.hpp"
#include "common/allocator.hpp"

#include <cstdint>
#include <memory>


namespace routing {
class Router;
}  // namespace routing

namespace proxyman::outbound {
class Handler;
class HandlerLookup;
}  // namespace proxyman::outbound

namespace features::policy {
class RequestPolicy;
}  // namespace features::policy
namespace app {
class SessionTrackingState;
class RequestLoadState;
namespace dns {
class DNS;
}  // namespace dns
}  // namespace app

class AwaitableTaskGroup;

namespace app::dispatcher {

namespace detail {
struct OutboundSelection;
}

// ============================================================================
// DefaultDispatcher - app/dispatcher implementation
//
// Stable session-domain orchestration: mutable request/tracking/outbound hosts
// share its executor; routing/policy snapshots are immutable control products.
// Hot dispatch consumes only the narrow DispatchPolicy.
// ============================================================================
class DefaultDispatcher final : public routing::Dispatcher, public memory::ThreadAllocated {
public:
    DefaultDispatcher(
        const routing::Router& router,
        proxyman::outbound::HandlerLookup& outbound_handlers,
        features::policy::RequestPolicy& request_policy,
        app::SessionTrackingState& session_tracking,
        app::dns::DNS& dns_service,
        app::RequestLoadState& request_load) noexcept;

    net::awaitable<RelayResult> Dispatch(
        net::io_context& io_context,
        const routing::DispatchPolicy& policy,
        std::unique_ptr<AsyncStream> inbound,
        transport::Link inbound_link,
        InitialPayload first_packet,
        session::Context& ctx,
        StatsShard& stats,
        const TimeoutsConfig& timeouts) override;

private:
    struct RouteResult {
        std::shared_ptr<proxyman::outbound::Handler> handler;
        ErrorCode error;
    };

    net::awaitable<void> DispatchPreparedLink(
        net::io_context& io_context,
        const routing::DispatchPolicy& policy,
        std::unique_ptr<AsyncStream> inbound,
        transport::Link inbound_link,
        InitialPayload first_packet,
        session::Context& ctx,
        StatsShard& stats,
        const TimeoutsConfig& timeouts,
        uint32_t pressure_idle_timeout,
        RelayResult& result,
        AwaitableTaskGroup& request_group,
        ErrorCode& cancellation_reason);
    [[nodiscard]] detail::OutboundSelection SelectRoute(
        session::Context& ctx,
        const routing::DispatchPolicy& policy) const;
    [[nodiscard]] RouteResult FinishRoute(
        session::Context& ctx,
        const detail::OutboundSelection& selection) const;
    [[nodiscard]] net::awaitable<RouteResult> RouteAsync(
        session::Context& ctx,
        const routing::DispatchPolicy& policy);

    const routing::Router& router_;
    proxyman::outbound::HandlerLookup& outbound_handlers_;
    features::policy::RequestPolicy& request_policy_;
    app::SessionTrackingState& session_tracking_;
    app::dns::DNS& dns_service_;
    app::RequestLoadState& request_load_;
};

}  // namespace app::dispatcher
