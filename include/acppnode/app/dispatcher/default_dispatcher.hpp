#pragma once

#include "acppnode/features/routing/dispatcher.hpp"

#include <cstdint>
#include <memory>
#include <string_view>

namespace acpp {

class Outbound;

namespace routing {
class Router;
}  // namespace routing

namespace features::outbound {
class Manager;
}  // namespace features::outbound

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
// 对齐 xray-core app/dispatcher.DefaultDispatcher 的实现职责。全部依赖在
// Worker 冷路径一次性构造；热路径只消费窄 DispatchPolicy，编排强制出口、
// Router 规则决策、显式 fallback 和通用请求策略。
// ============================================================================
class DefaultDispatcher final : public routing::Dispatcher {
public:
    DefaultDispatcher(
        const routing::Router& router,
        features::outbound::Manager& outbound_manager,
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
        std::shared_ptr<Outbound> handler;
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
    [[nodiscard]] std::shared_ptr<Outbound> ResolveOutboundHandler(
        std::string_view tag) const noexcept;
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
    features::outbound::Manager& outbound_manager_;
    features::policy::RequestPolicy& request_policy_;
    app::SessionTrackingState& session_tracking_;
    app::dns::DNS& dns_service_;
    app::RequestLoadState& request_load_;
};

}  // namespace app::dispatcher
}  // namespace acpp
