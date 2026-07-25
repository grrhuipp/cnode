#pragma once

#include "acppnode/app/proxyman/inbound/receiver_settings.hpp"
#include "acppnode/app/stats.hpp"
#include "acppnode/features/routing/dispatcher.hpp"
#include "acppnode/infra/config_types.hpp"
#include "acppnode/proxy/inbound.hpp"
#include "acppnode/transport/async_stream.hpp"

#include <memory>
#include <string_view>

namespace acpp::app {
class RequestLoadState;
}

namespace acpp::proxyman::inbound {

// ============================================================================
// Handler - per-Worker inbound handler
//
// 对齐 xray-core features/inbound.Handler 的职责：一个 handler 绑定 tag、
// receiver settings 和 proxy.Inbound 实例。Worker 仍拥有
// SO_REUSEPORT socket，但不再分散持有 receiver settings 与协议对象。
// ============================================================================
class Handler final : public std::enable_shared_from_this<Handler> {
public:
    Handler(inbound::ReceiverSettings receiver, std::unique_ptr<Inbound> proxy);

    Handler(const Handler&) = delete;
    Handler& operator=(const Handler&) = delete;
    Handler(Handler&&) = delete;
    Handler& operator=(Handler&&) = delete;

    [[nodiscard]] std::string_view Tag() const noexcept {
        return receiver_.inbound_tag;
    }

    [[nodiscard]] const inbound::ReceiverSettings& ReceiverSettings() const noexcept {
        return receiver_;
    }

    net::awaitable<void> ProcessAcceptedTCP(
        net::io_context& io_context,
        routing::Dispatcher& dispatcher,
        StatsShard& stats,
        app::RequestLoadState& request_load,
        const TimeoutsConfig& timeouts,
        std::unique_ptr<AsyncStream> raw_conn,
        session::Context& ctx);

private:
    class LogicalTransportStreamSink;

    net::awaitable<void> ProcessPreparedTransportStream(
        net::io_context& io_context,
        routing::Dispatcher& dispatcher,
        StatsShard& stats,
        app::RequestLoadState& request_load,
        const TimeoutsConfig& timeouts,
        std::unique_ptr<AsyncStream> stream,
        session::Context& ctx);

    inbound::ReceiverSettings receiver_;
    std::unique_ptr<Inbound> proxy_;
};

}  // namespace acpp::proxyman::inbound
