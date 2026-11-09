#pragma once

#include "app/dns/dns.hpp"
#include "outbound_stream_endpoint.hpp"
#include "common/ip_utils.hpp"
#include "common/target_address.hpp"
#include "transport/internet/datagram_socket.hpp"
#include "transport/link.hpp"
#include "transport/link_error.hpp"

#include <asio/as_tuple.hpp>
#include <asio/experimental/awaitable_operators.hpp>
#include <asio/experimental/channel.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/this_coro.hpp>

#include <tl/expected.hpp>
namespace proxy {

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
    UdpRequest(net::io_context& io, app::dns::DNS& dns,
               const net::ip::address& bind_address)
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
