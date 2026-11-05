#pragma once

#include "acppnode/common/allocator.hpp"
#include "acppnode/app/rate_limiter.hpp"
#include "acppnode/app/proxyman/inbound/receiver_settings.hpp"
#include "acppnode/app/stats.hpp"
#include "acppnode/features/routing/dispatcher.hpp"
#include "acppnode/infra/config_types.hpp"
#include "acppnode/proxy/inbound.hpp"
#include "acppnode/transport/async_stream.hpp"
#include "acppnode/transport/internet/transport_security.hpp"

#include <memory>
#include <string_view>

namespace acpp::app {
class RequestLoadState;
namespace dns {
class DNS;
}  // namespace dns
}  // namespace acpp::app

namespace acpp::proxyman::inbound {

// ============================================================================
// Handler - address-stable session-domain inbound transport host.
// Listener descriptors may use an eagerly prepared protocol; physical domains
// create protocol state only when a real logical request reaches the proxy.
// ============================================================================
class Handler final
    : public memory::ThreadAllocated
    , public std::enable_shared_from_this<Handler> {
public:
    class ProtocolProvider {
    public:
        virtual ~ProtocolProvider() = default;
        virtual Inbound& GetProxy() = 0;
    };
    // Prepared TransportSecurity is shared; SSL contexts are never rebuilt for
    // each short HTTP packet upload.
    Handler(inbound::ReceiverSettings receiver, std::unique_ptr<Inbound> proxy,
            ConnectionLimiter& limiter);
    Handler(inbound::ReceiverSettings receiver, ProtocolProvider& provider,
            ConnectionLimiter& limiter);

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
        session::Context& ctx,
        app::dns::DNS* dns_service = nullptr);

private:
    class LogicalTransportStreamSink;

    net::awaitable<void> ProcessPreparedTransportStream(
        net::io_context& io_context,
        routing::Dispatcher& dispatcher,
        StatsShard& stats,
        app::RequestLoadState& request_load,
        const TimeoutsConfig& timeouts,
        std::unique_ptr<AsyncStream> stream,
        session::Context& ctx,
        const std::shared_ptr<ConnectionLimiter::Family>& family);

    inbound::ReceiverSettings receiver_;
    TransportSecurity security_;
    std::unique_ptr<Inbound> proxy_;
    ProtocolProvider* provider_ = nullptr;
    ConnectionLimiter& limiter_;
};

}  // namespace acpp::proxyman::inbound
