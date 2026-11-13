#pragma once

#include "routing/dispatcher.hpp"
#include "app/relay.hpp"
#include "routing/router.hpp"

#include <cassert>
#include <cstdint>
#include <memory>
#include <optional>
#include <string_view>
#include <variant>

namespace common {
class DetectRulePolicy;
}  // namespace common
namespace app {
class OutboundHandler;
class OutboundHandlerRegistry;
class SessionTrackingState;
class RequestLoadState;
class DNS;

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

// The result borrows an owning policy tag; reject temporaries and implicit
// ForceOutbound/RouteWithFallback-to-variant conversions at the call boundary.
OutboundSelection SelectOutbound(
    const routing::OutboundSelectionPolicy&&,
    const routing::RouteDecision& = {}) noexcept = delete;



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
        const OutboundHandlerRegistry& outbound_handlers,
        common::DetectRulePolicy& request_policy,
        app::SessionTrackingState& session_tracking,
        app::DNS& dns_service,
        app::RequestLoadState& request_load) noexcept;

    net::awaitable<RelayResult> Dispatch(
        net::io_context& io_context,
        const routing::DispatchPolicy& policy,
        std::unique_ptr<transport::AsyncStream> inbound,
        transport::Link inbound_link,
        common::InitialPayload first_packet,
        common::Context& ctx,
        StatsShard& stats,
        const infra::TimeoutsConfig& timeouts) override;

private:
    struct RouteResult {
        std::shared_ptr<OutboundHandler> handler;
        common::ErrorCode error;
    };

    net::awaitable<void> DispatchPreparedLink(
        net::io_context& io_context,
        const routing::DispatchPolicy& policy,
        std::unique_ptr<transport::AsyncStream> inbound,
        transport::Link inbound_link,
        common::InitialPayload& first_packet,
        common::Context& ctx,
        StatsShard& stats,
        const infra::TimeoutsConfig& timeouts,
        uint32_t pressure_idle_timeout,
        RelayResult& result,
        common::ErrorCode& cancellation_reason);
    [[nodiscard]] OutboundSelection SelectRoute(
        common::Context& ctx,
        const routing::DispatchPolicy& policy) const;
    [[nodiscard]] RouteResult FinishRoute(
        common::Context& ctx,
        const OutboundSelection& selection) const;
    [[nodiscard]] net::awaitable<RouteResult> RouteAsync(
        common::Context& ctx,
        const routing::DispatchPolicy& policy,
        std::optional<OutboundSelection> initial_selection);

    const routing::Router& router_;
    const OutboundHandlerRegistry& outbound_handlers_;
    common::DetectRulePolicy& request_policy_;
    app::SessionTrackingState& session_tracking_;
    app::DNS& dns_service_;
    app::RequestLoadState& request_load_;
};

}  // namespace app
