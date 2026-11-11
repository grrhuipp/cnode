#pragma once

#include "app/dns/dns.hpp"
#include "common/ip_utils.hpp"
#include "common/target_address.hpp"
#include "infra/config_types.hpp"
#include "infra/log.hpp"
#include "transport/async_stream.hpp"
#include "transport/link.hpp"
#include "transport/internet/datagram_socket.hpp"
#include "transport/internet/outbound_target_builder.hpp"
#include "transport/internet/stream_settings.hpp"

#include <asio/as_tuple.hpp>
#include <asio/experimental/awaitable_operators.hpp>
#include <asio/experimental/channel.hpp>
#include <asio/this_coro.hpp>
#include <asio/use_awaitable.hpp>

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <tl/expected.hpp>
#include <utility>

namespace proxy {

class OutboundStreamEndpointBase
    : public transport::MultiBufferReader
    , public transport::MultiBufferWriter {
public:
    explicit OutboundStreamEndpointBase(AsyncStream& stream) noexcept
        : stream_(stream) {}

    bool ConsumeIdleTimeout() noexcept {
        return stream_.ConsumeIdleTimeout();
    }

    bool ConsumeReadTimeout() noexcept {
        return stream_.ConsumeReadTimeout();
    }

    bool ConsumeWriteTimeout() noexcept {
        return stream_.ConsumeWriteTimeout();
    }

    PhaseDeadlineHandle StartPhaseDeadline(std::chrono::seconds timeout) {
        return stream_.StartPhaseDeadline(timeout);
    }

    void ClearPhaseDeadline() {
        stream_.ClearPhaseDeadline();
    }

    bool ConsumePhaseDeadline() noexcept {
        return stream_.ConsumePhaseDeadline();
    }

    void Cancel() noexcept {
        stream_.Cancel();
    }

    void SetWriteTimeout(std::chrono::seconds timeout) {
        stream_.SetWriteTimeout(timeout);
    }

    void Close() {
        stream_.Close();
    }

    void CloseAbortive() {
        stream_.CloseAbortive();
    }

    transport::CancellationSource& Cancellation() noexcept override {
        return stream_.Cancellation();
    }

    transport::EofAction ReadEofAction() const noexcept override {
        return stream_.ReadEofAction();
    }

    bool WriteShutdownClosesLink() const noexcept override {
        return stream_.WriteShutdownClosesLink();
    }

protected:
    AsyncStream& stream_;
};

class OutboundDatagramEndpointBase
    : public transport::MultiBufferReader
    , public transport::MultiBufferWriter {
public:
    OutboundDatagramEndpointBase(net::io_context& io, const net::ip::address& bind_address)
        : socket_(io, bind_address) {}

    net::awaitable<void> WriteBuffers(std::span<const net::const_buffer> buffers) override {
        return WriteBuffersAsMultiBuffer(buffers);
    }

    net::awaitable<void> AsyncShutdownWrite() override {
        write_closed_ = true;
        co_return;
    }

    void Cancel() noexcept {
        socket_.Cancel();
    }

    void Close() noexcept {
        socket_.Close();
    }

    transport::CancellationSource& Cancellation() noexcept override {
        return socket_.Cancellation();
    }

    void SetIdleTimeout(std::chrono::seconds value) {
        socket_.SetIdleTimeout(value);
    }

    void SetReadTimeout(std::chrono::seconds value) {
        socket_.SetReadTimeout(value);
    }

    void SetWriteTimeout(std::chrono::seconds value) {
        socket_.SetWriteTimeout(value);
    }

    PhaseDeadlineHandle StartPhaseDeadline(std::chrono::seconds value) {
        return socket_.StartPhaseDeadline(value);
    }

    void ClearPhaseDeadline() noexcept {
        socket_.ClearPhaseDeadline();
    }

    bool ConsumeIdleTimeout() noexcept {
        return socket_.ConsumeIdleTimeout();
    }

    bool ConsumeReadTimeout() noexcept {
        return socket_.ConsumeReadTimeout();
    }

    bool ConsumeWriteTimeout() noexcept {
        return socket_.ConsumeWriteTimeout();
    }

    bool ConsumePhaseDeadline() noexcept {
        return socket_.ConsumePhaseDeadline();
    }

protected:
    transport::internet::DatagramSocket socket_;
    bool write_closed_ = false;
};

// Cold-path result for a proxy protocol with a next hop: the validated server
// and the Handler's sender settings (sendThrough is applied by proxyman).
struct PreparedNextHop {
    OutboundServer server;
    OutboundSenderSettings sender;
};

// The one application of a protocol's stream defaults (TLS requirement,
// fallback SNI, ALPN) to the source streamSettings. Without an explicit
// fallback server name the next hop's address is used.
[[nodiscard]] inline StreamSettings PrepareOutboundStream(
    const infra::OutboundSourceConfig& source,
    const OutboundServer& server,
    OutboundStreamDefaults defaults) {
    if (defaults.fallback_server_name.empty()) {
        defaults.fallback_server_name = server.address;
    }
    auto settings = NormalizeOutboundStreamSettings(source.stream_settings, defaults);
    TransportSecurity::Prepare(settings, StreamEndpointRole::Outbound);
    return settings;
}

[[nodiscard]] inline std::optional<PreparedNextHop> PrepareNextHop(
    const infra::OutboundSourceConfig& source,
    std::string address,
    uint16_t port,
    const OutboundStreamDefaults& defaults) {
    auto server = MakeOutboundServer(std::move(address), port);
    if (!server) {
        LOG_ERROR("{} outbound '{}': {}", source.protocol, source.tag, server.error());
        return std::nullopt;
    }
    PreparedNextHop prepared{.server = std::move(*server), .sender = {}};
    prepared.sender.stream_settings = PrepareOutboundStream(source, prepared.server, defaults);
    return prepared;
}

// Validates an optional Xray-style single-element object array (e.g. "servers"
// or "vnext"). Returns nullptr when absent, the single object when valid, or
// std::nullopt on a malformed present field (Fail-Closed).
[[nodiscard]] inline std::optional<const json::object*>
ParseOptionalSingleObjectArray(
    const json::object& parent,
    std::string_view key,
    std::string_view protocol,
    std::string_view tag) {
    const auto* value = parent.if_contains(key);
    if (!value) {
        return static_cast<const json::object*>(nullptr);
    }
    if (!value->is_array() ||
        value->as_array().size() != 1 ||
        !value->as_array()[0].is_object()) {
        LOG_ERROR("{} outbound '{}': {} must be a single-element object array",
                  protocol, tag, key);
        return std::nullopt;
    }
    return &value->as_array()[0].as_object();
}

[[nodiscard]] inline const json::object*
ParseRequiredSingleObjectArray(
    const json::object& parent,
    std::string_view key,
    std::string_view protocol,
    std::string_view tag) {
    const auto parsed = ParseOptionalSingleObjectArray(parent, key, protocol, tag);
    if (!parsed) {
        return nullptr;
    }
    if (!*parsed) {
        LOG_ERROR("{} outbound '{}': {} must be a single-element object array",
                  protocol, tag, key);
        return nullptr;
    }
    return *parsed;
}


// Outbound-only endpoint preparation. A packet's target and payload remain
// owned by its logical write until DNS and socket I/O have both finished.
// The transport knows only the resulting IP endpoint, never DNS or routing.
inline net::awaitable<tl::expected<udp::endpoint, ErrorCode>> ResolveUdpEndpoint(
    app::dns::DNS& dns,
    const TargetAddress& target,
    transport::internet::DatagramSocket& socket,
    const transport::internet::DatagramSocket::WriteOperation& write) {
    const auto parent_cancellation = co_await net::this_coro::cancellation_state;
    if (write.Cancelled()) co_return tl::unexpected(write.CancellationReason());
    if (parent_cancellation.cancelled() != net::cancellation_type::none)
        co_return tl::unexpected(ErrorCode::CANCELLED);
    if (!target.IsValid()) co_return tl::unexpected(ErrorCode::INVALID_ARGUMENT);
    if (target.resolved_addr) {
        if (target.resolved_addr->is_v6() != socket.IsIPv6())
            co_return tl::unexpected(ErrorCode::INVALID_ARGUMENT);
        co_return udp::endpoint(*target.resolved_addr, target.port);
    }
    if (!target.IsDomain()) co_return tl::unexpected(ErrorCode::INVALID_ARGUMENT);

    struct CancellationWait final : transport::CancellationSubscription {
        explicit CancellationWait(net::any_io_executor executor)
            : wake(std::move(executor), 1) {}
        SignalChannel wake;
        ErrorCode reason = ErrorCode::OK;

    private:
        void OnCancellation(transport::Cancellation event) noexcept override {
            reason = event.reason;
            wake.close();
        }
    } cancellation(co_await net::this_coro::executor);
    cancellation.Resubscribe(socket.Cancellation());
    if (cancellation.reason != ErrorCode::OK)
        co_return tl::unexpected(cancellation.reason);

    // Both race participants return values even on cancellation: operator||
    // cancels and joins the loser before this scope releases borrowed state.
    auto resolve = [&]() -> net::awaitable<tl::expected<udp::endpoint, ErrorCode>> {
        try {
            auto answer = co_await dns.Resolve(target.host);
            if (!answer.Ok()) co_return tl::unexpected(answer.error);
            for (const auto& address : answer.addresses) {
                if (!address.is_unspecified() && address.is_v6() == socket.IsIPv6())
                    co_return udp::endpoint(address, target.port);
            }
            co_return tl::unexpected(ErrorCode::DNS_NO_RECORD);
        } catch (const transport::LinkError& error) {
            co_return tl::unexpected(error.code());
        } catch (const IoSystemError& error) {
            co_return tl::unexpected(MapAsioError(error.code()));
        } catch (const std::bad_alloc&) {
            co_return tl::unexpected(ErrorCode::RESOURCE_EXHAUSTED);
        } catch (...) {
            co_return tl::unexpected(ErrorCode::INTERNAL);
        }
    };
    auto cancelled = [&]() -> net::awaitable<ErrorCode> {
        (void)co_await cancellation.wake.async_receive(net::as_tuple(net::use_awaitable));
        co_return cancellation.reason == ErrorCode::OK ? ErrorCode::CANCELLED : cancellation.reason;
    };
    using namespace net::experimental::awaitable_operators;
    try {
        auto result = co_await (resolve() || cancelled());
        if (write.Cancelled()) co_return tl::unexpected(write.CancellationReason());
        if (cancellation.reason != ErrorCode::OK) co_return tl::unexpected(cancellation.reason);
        if (parent_cancellation.cancelled() != net::cancellation_type::none)
            co_return tl::unexpected(ErrorCode::CANCELLED);
        if (result.index() == 1) co_return tl::unexpected(std::get<1>(result));
        co_return std::move(std::get<0>(result));
    } catch (const IoSystemError& error) {
        co_return tl::unexpected(MapAsioError(error.code()));
    } catch (const std::bad_alloc&) {
        co_return tl::unexpected(ErrorCode::RESOURCE_EXHAUSTED);
    } catch (...) {
        // Parent cancellation may abort both race participants before either
        // reports success. The race has still joined them before throwing.
        if (write.Cancelled()) co_return tl::unexpected(write.CancellationReason());
        if (parent_cancellation.cancelled() != net::cancellation_type::none)
            co_return tl::unexpected(ErrorCode::CANCELLED);
        co_return tl::unexpected(ErrorCode::INTERNAL);
    }
}
}  // namespace proxy

namespace proxy::freedom::outbound {

// One direct UDP association. Target resolution belongs to this outbound;
// its concrete transport owns the socket, byte I/O and aggregate deadlines.
class UdpRequest final : public ::proxy::OutboundDatagramEndpointBase {
public:
    UdpRequest(net::io_context& io, app::dns::DNS& dns, const net::ip::address& bind_address)
        : OutboundDatagramEndpointBase(io, bind_address), dns_(dns) {}

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
        auto read = socket_.StartRead();
        for (;;) {
            auto packet = co_await read.Receive();
            if (packet.source.port() == 0) {
                continue;
            }
            const TargetAddress source(iputil::NormalizeAddress(packet.source.address()),
                                       packet.source.port());
            if (!buf::SetUdpTarget(packet.payload, source))
                throw transport::LinkError(ErrorCode::RESOURCE_EXHAUSTED);
            socket_.TouchActivity();
            co_return std::move(packet.payload);
        }
    }

    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer payload) override {
        const auto datagram = buf::InspectUdpDatagram(payload);
        if (datagram.status == buf::UdpDatagramStatus::Empty) co_return;
        if (!datagram.Valid() || !datagram.target || !datagram.target->IsValid())
            throw transport::LinkError(ErrorCode::INVALID_ARGUMENT);
        if (write_closed_) throw transport::WriteClosed{};
        auto write = socket_.StartWrite();
        if (datagram.target->resolved_addr) {
            if (datagram.target->resolved_addr->is_v6() != socket_.IsIPv6())
                throw transport::LinkError(ErrorCode::INVALID_ARGUMENT);
            co_await write.SendTo(udp::endpoint(*datagram.target->resolved_addr, datagram.target->port),
                                 std::move(payload));
        } else {
            auto target = co_await ResolveUdpEndpoint(dns_, *datagram.target, socket_, write);
            if (!target) throw transport::LinkError(target.error());
            co_await write.SendTo(*target, std::move(payload));
        }
    }
private:
    app::dns::DNS& dns_;
};

}  // namespace proxy::freedom::outbound
