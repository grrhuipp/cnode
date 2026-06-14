#pragma once

#include "acppnode/features/routing/dispatcher.hpp"
#include "acppnode/app/relay_types.hpp"
#include "acppnode/app/stats.hpp"
#include "acppnode/common/initial_payload.hpp"
#include "acppnode/infra/config_types.hpp"
#include "acppnode/transport/async_stream.hpp"
#include "acppnode/transport/link.hpp"

#include <memory>
#include <string_view>

namespace acpp {

namespace app::router {
class Router;
}  // namespace app::router

namespace features::outbound {
class Manager;
class Handler;
}  // namespace features::outbound

namespace rule {
class Manager;
}  // namespace rule
namespace app {
class SessionTrackingState;
}  // namespace app

namespace app::dispatcher {

// ============================================================================
// DefaultDispatcher - app/dispatcher implementation
//
// 对齐 xray-core app/dispatcher.DefaultDispatcher 的实现职责。Router 和
// outbound 表仍在 Worker 冷路径完成绑定；热路径 Dispatch 只做固定出口检查
// 和 Router::Route 调用。
// ============================================================================
class DefaultDispatcher final : public routing::Dispatcher {
public:
    DefaultDispatcher() = default;
    explicit DefaultDispatcher(app::router::Router& router) noexcept;

    void BindRouter(app::router::Router& router) noexcept;
    void BindOutboundManager(features::outbound::Manager& outbound_manager) noexcept;
    void BindRuleManager(rule::Manager& rule_manager) noexcept;
    void BindSessionTracking(app::SessionTrackingState& session_tracking) noexcept;

    net::awaitable<RelayResult> Dispatch(
        net::io_context& io_context,
        const proxyman::inbound::ReceiverSettings& receiver,
        std::unique_ptr<AsyncStream> inbound,
        transport::Link inbound_link,
        InitialPayload first_packet,
        session::Context& ctx,
        StatsShard& stats,
        const TimeoutsConfig& timeouts,
        uint32_t pressure_idle_timeout = 0) override;

    [[nodiscard]] routing::DispatchResult Route(
        session::Context& ctx,
        const proxyman::inbound::ReceiverSettings& receiver) const noexcept override;
    [[nodiscard]] routing::DispatchResult Route(session::Context& ctx) const noexcept override;

    [[nodiscard]] net::awaitable<UDPSession*> DispatchUDP(
        session::Context& ctx,
        const proxyman::inbound::ReceiverSettings* receiver = nullptr) override;

private:
    net::awaitable<RelayResult> DispatchPreparedLink(
        net::io_context& io_context,
        const proxyman::inbound::ReceiverSettings& receiver,
        std::unique_ptr<AsyncStream> inbound,
        transport::Link inbound_link,
        InitialPayload first_packet,
        session::Context& ctx,
        StatsShard& stats,
        const TimeoutsConfig& timeouts,
        uint32_t pressure_idle_timeout);
    [[nodiscard]] features::outbound::Handler* ResolveOutboundHandler(
        std::string_view tag) const noexcept;

    app::router::Router* router_ = nullptr;
    features::outbound::Manager* outbound_manager_ = nullptr;
    rule::Manager* rule_manager_ = nullptr;
    app::SessionTrackingState* session_tracking_ = nullptr;
};

}  // namespace app::dispatcher
}  // namespace acpp
