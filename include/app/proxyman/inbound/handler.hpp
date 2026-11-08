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
    // Plain cold inputs for building the protocol handler on first use.
    struct LazyProtocol {
        std::shared_ptr<const BuildRequest> prepared;
        StatsShard* stats = nullptr;
        ConnectionLimiter* limiter = nullptr;
    };
    // Prepared TransportSecurity is shared; SSL contexts are never rebuilt for
    // each short HTTP packet upload.
    Handler(inbound::ReceiverSettings receiver, std::unique_ptr<Inbound> proxy,
            ConnectionLimiter& limiter);
    Handler(std::shared_ptr<const inbound::ReceiverSettings> receiver,
            std::unique_ptr<Inbound> proxy,
            ConnectionLimiter& limiter);
    Handler(std::shared_ptr<const inbound::ReceiverSettings> receiver,
            LazyProtocol lazy,
            ConnectionLimiter& limiter);

    Handler(const Handler&) = delete;
    Handler& operator=(const Handler&) = delete;
    Handler(Handler&&) = delete;
    Handler& operator=(Handler&&) = delete;

    [[nodiscard]] std::string_view Tag() const noexcept {
        return receiver_->inbound_tag;
    }

    [[nodiscard]] const inbound::ReceiverSettings& ReceiverSettings() const noexcept {
        return *receiver_;
    }

    [[nodiscard]] const std::shared_ptr<const inbound::ReceiverSettings>&
    SharedReceiverSettings() const noexcept {
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

    // Null until a lazily built protocol has handled its first request.
    [[nodiscard]] const ProtocolRuntime* Runtime() const noexcept {
        return runtime_.get();
    }
    // Releases lazily built protocol state; the caller has joined all requests.
    void ReleaseProtocol() noexcept;

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

    std::shared_ptr<const inbound::ReceiverSettings> receiver_;
    TransportSecurity security_;
    LazyProtocol lazy_;
    std::unique_ptr<ProtocolRuntime> runtime_;
    std::unique_ptr<Inbound> proxy_;
    ConnectionLimiter& limiter_;
};

}  // namespace proxyman::inbound
