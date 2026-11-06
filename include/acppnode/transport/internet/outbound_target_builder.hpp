#pragma once

#include "acppnode/common/asio_types.hpp"
#include "acppnode/common/defaults.hpp"
#include "acppnode/common/error.hpp"
#include "acppnode/transport/async_stream.hpp"
#include "acppnode/transport/link_error.hpp"
#include "acppnode/transport/internet/dial_target.hpp"
#include "acppnode/transport/internet/outbound_bind.hpp"
#include "acppnode/transport/internet/outbound_sender.hpp"
#include "acppnode/transport/internet/stream_settings.hpp"
#include "acppnode/transport/internet/transport_security.hpp"

#include <chrono>
#include <memory>
#include <optional>
#include <span>
#include <string_view>
#include <tl/expected.hpp>
#include <utility>

namespace acpp::app::dns {
class DNS;
}  // namespace acpp::app::dns

namespace acpp {

namespace session {
struct Context;
}  // namespace session

struct OutboundTargetOptions {
    app::dns::DNS* dns_service = nullptr;
    std::string_view address{};
    std::optional<net::ip::address> literal_address = std::nullopt;
    uint16_t port = 0;
    const StreamSettings* stream_settings = nullptr;
    // The outbound handler's contexts for |stream_settings|; the XHTTP
    // download leg uses its XHttpDownload() contexts.
    const TransportSecurity* security = nullptr;
    std::chrono::seconds timeout{defaults::kDialTimeout};
    const OutboundBind* send_through = nullptr; // Borrowed from the outbound handler.
    const tcp::endpoint* inbound_local_addr = nullptr;
    std::string_view inbound_source_ip{};
    uint16_t inbound_source_port = 0;
    std::optional<OutboundBind::Selection> ordered_bind_v4 = std::nullopt;
    std::optional<OutboundBind::Selection> ordered_bind_v6 = std::nullopt;
};

[[nodiscard]] std::string_view ResolveOutboundTlsServerName(
    const StreamSettings& settings,
    std::string_view fallback_server_name);

[[nodiscard]]
net::awaitable<tl::expected<OutboundTransportTarget, ErrorCode>>
BuildOutboundTransportTarget(OutboundTargetOptions options);

// ============================================================================
// OutboundDialer - Xray internet.Dialer of one proxyman outbound Handler
//
// The Handler owns it next to its sender settings and passes it by reference
// into proxy::Outbound::Process. Every outbound connection of that tag leaves
// through here: the stream settings, transport security and sendThrough are the
// Handler's, never a protocol's private copy. Bound to the executing domain's
// reactor and DNS client; the sender settings must outlive the dialer.
// ============================================================================
class OutboundDialer final {
public:
    // Per-request sendThrough choice for Ordered binds, computed once so that a
    // caller can match pooled transports against the same selection it dials.
    struct OrderedBind {
        OutboundBind::Selection v4;
        OutboundBind::Selection v6;
    };

    // Remote side of a native (transport-less) UDP association.
    struct DatagramRemote {
        // Known remote address; fixes the socket family.
        std::optional<net::ip::address> address;
        // Family hint when the remote is a hostname (e.g. a routing lookup).
        std::optional<net::ip::address> family_hint;
        bool accepts_v4 = true;
        bool accepts_v6 = true;
        bool prefers_v6 = false;
    };

    OutboundDialer(net::io_context& io_context,
                   app::dns::DNS& dns,
                   const OutboundSenderSettings& sender,
                   std::chrono::seconds timeout);
    OutboundDialer(const OutboundDialer&) = delete;
    OutboundDialer& operator=(const OutboundDialer&) = delete;

    [[nodiscard]] net::io_context& IoContext() const noexcept { return io_context_; }
    [[nodiscard]] app::dns::DNS& Dns() const noexcept { return dns_; }

    // Empty unless sendThrough is Ordered.
    [[nodiscard]] std::optional<OrderedBind> SelectOrderedBind(
        const session::Context& ctx) const;

    // Proxy next hop through the Handler's stream settings.
    [[nodiscard]] net::awaitable<tl::expected<std::unique_ptr<AsyncStream>, ErrorCode>>
    Dial(session::Context& ctx, const OutboundServer& server,
         const OrderedBind* ordered = nullptr);

    // Destination already resolved by protocol policy (Freedom domainStrategy);
    // candidates are tried in the given order.
    [[nodiscard]] net::awaitable<tl::expected<std::unique_ptr<AsyncStream>, ErrorCode>>
    Dial(session::Context& ctx, std::span<const net::ip::address> addresses, uint16_t port);

    // Native UDP association: selects the sendThrough bind address, constructs
    // Endpoint(io_context, dns, bind_address, args...) and records the egress.
    template <typename Endpoint, typename... Args>
    [[nodiscard]] tl::expected<void, ErrorCode> OpenDatagram(
        session::Context& ctx, const DatagramRemote& remote,
        std::optional<Endpoint>& endpoint, Args&&... args) {
        auto bind = SelectDatagramBind(ctx, remote);
        if (!bind) return tl::unexpected(bind.error());
        try {
            endpoint.emplace(io_context_, dns_, *bind, std::forward<Args>(args)...);
        } catch (const transport::LinkError& error) {
            ReportDatagramFailure(ctx, *bind, error.what());
            return tl::unexpected(error.code());
        } catch (const IoSystemError& error) {
            ReportDatagramFailure(ctx, *bind, error.what());
            return tl::unexpected(MapAsioError(error.code()));
        }
        RecordEgress(ctx, *bind);
        return {};
    }

    // Records the egress of a pooled transport reused for this request, exactly
    // as a fresh dial does (connected local address and access log).
    void RecordConnected(session::Context& ctx, const AsyncStream& stream) const;

private:
    [[nodiscard]] net::awaitable<tl::expected<std::unique_ptr<AsyncStream>, ErrorCode>>
    DialTarget(session::Context& ctx, const OutboundTransportTarget& target);
    [[nodiscard]] tl::expected<net::ip::address, ErrorCode> SelectDatagramBind(
        const session::Context& ctx, const DatagramRemote& remote) const;
    void ReportDatagramFailure(const session::Context& ctx,
                               const net::ip::address& bind,
                               std::string_view reason) const;
    void RecordEgress(session::Context& ctx,
                      const std::optional<net::ip::address>& local) const;

    net::io_context& io_context_;
    app::dns::DNS& dns_;
    const OutboundSenderSettings& sender_;
    TransportSecurity security_;  // This domain's contexts for sender_.stream_settings.
    std::chrono::seconds timeout_;
};

}  // namespace acpp
