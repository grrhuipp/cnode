#pragma once

#include "features/routing/dispatcher.hpp"
#include "app/relay.hpp"
#include "features/routing/router.hpp"
#include "common/allocator.hpp"

#include <cassert>
#include <cstdint>
#include <memory>
#include <optional>
#include <string_view>
#include <variant>

namespace proxyman::outbound {
class Handler;
class HandlerLookup;
}  // namespace proxyman::outbound

namespace rule {
class DetectRulePolicy;
}  // namespace rule
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

enum class SelectionSource : uint8_t {
    Forced,
    Rule,
    Fallback,
};

struct OutboundSelection {
    std::string_view outbound_tag;
    SelectionSource source = SelectionSource::Fallback;
};

[[nodiscard]] inline bool RequiresRouting(
    const routing::OutboundSelectionPolicy& policy) noexcept {
    return std::holds_alternative<routing::RouteWithFallback>(policy);
}

[[nodiscard]] inline OutboundSelection SelectOutbound(
    const routing::OutboundSelectionPolicy& policy,
    const routing::RouteDecision& rule = {}) noexcept {
    if (const auto* forced = std::get_if<routing::ForceOutbound>(&policy)) {
        return OutboundSelection{forced->outbound_tag, SelectionSource::Forced};
    }

    const auto* routed = std::get_if<routing::RouteWithFallback>(&policy);
    assert(routed != nullptr);
    if (rule.matched) {
        return OutboundSelection{rule.outbound_tag, SelectionSource::Rule};
    }
    return OutboundSelection{routed->outbound_tag, SelectionSource::Fallback};
}

}  // namespace detail

// ============================================================================
// DefaultDispatcher - app/dispatcher implementation
//
// Stable session-domain orchestration: mutable request/tracking/outbound hosts
// share its executor; routing/policy snapshots are immutable control products.
// Hot dispatch consumes only the narrow DispatchPolicy.
// ============================================================================
class DefaultDispatcher final : public routing::Dispatcher {
public:
    DefaultDispatcher(
        const routing::Router& router,
        proxyman::outbound::HandlerLookup& outbound_handlers,
        rule::DetectRulePolicy& request_policy,
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
        InitialPayload& first_packet,
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
        const routing::DispatchPolicy& policy,
        std::optional<detail::OutboundSelection> initial_selection);

    const routing::Router& router_;
    proxyman::outbound::HandlerLookup& outbound_handlers_;
    rule::DetectRulePolicy& request_policy_;
    app::SessionTrackingState& session_tracking_;
    app::dns::DNS& dns_service_;
    app::RequestLoadState& request_load_;
};

}  // namespace app::dispatcher
