#pragma once

#include "common/allocator.hpp"
#include "app/rate_limiter.hpp"
#include "app/proxyman/inbound/receiver_settings.hpp"
#include "app/proxyman/inbound/factory.hpp"
#include "app/stats.hpp"
#include "features/routing/dispatcher.hpp"
#include "infra/config_types.hpp"
#include "proxy/inbound.hpp"
#include "transport/async_stream.hpp"
#include "transport/internet/transport_security.hpp"

#include <memory>
#include <string_view>

namespace app {
class RequestLoadState;
namespace dns {
class DNS;
}  // namespace dns
}  // namespace app

class InboundTransportStreamHandler;

namespace proxyman::inbound {

// ============================================================================
// Handler - address-stable session-domain inbound transport host.
// Listener descriptors may use an eagerly prepared protocol; physical domains
// create protocol state only when a real logical request reaches the proxy.
// Either way each request crosses exactly one virtual Inbound::Process.
// ============================================================================
class Handler final
    : public memory::ThreadAllocated
    , public std::enable_shared_from_this<Handler> {
public:
    // Prepared TransportSecurity is shared; SSL contexts are never rebuilt for
    // each short HTTP packet upload.
    Handler(inbound::ReceiverSettings receiver, std::unique_ptr<Inbound> proxy,
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

    // Logical-stream sink for a transport session that authenticated its
    // client itself (Hysteria QUIC, as Xray's hysteria hub). Each delivered
    // stream runs ProcessPreparedTransportStream with a child of |session_ctx|
    // that keeps the session's identity and client endpoint, and takes a
    // logical admission under the session's physical |family|.
    [[nodiscard]] std::shared_ptr<InboundTransportStreamHandler>
    NewAuthenticatedStreamSink(
        net::io_context& io_context,
        routing::Dispatcher& dispatcher,
        StatsShard& stats,
        app::RequestLoadState& request_load,
        const TimeoutsConfig& timeouts,
        const session::Context& session_ctx,
        std::shared_ptr<ConnectionLimiter::Family> family);


private:
    class LogicalTransportStreamSink;

    Inbound& Proxy();

    net::awaitable<void> ProcessPreparedTransportStream(
        net::io_context& io_context,
        routing::Dispatcher& dispatcher,
        StatsShard& stats,
        app::RequestLoadState& request_load,
        const TimeoutsConfig& timeouts,
        std::unique_ptr<AsyncStream> stream,
        session::Context& ctx,
        const std::shared_ptr<ConnectionLimiter::Family>& family);

    const inbound::ReceiverSettings receiver_;
    TransportSecurity security_;
    std::unique_ptr<Inbound> proxy_;
    ConnectionLimiter& limiter_;
};

}  // namespace proxyman::inbound
