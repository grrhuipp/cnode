#pragma once

#include "acppnode/app/dns/dns.hpp"
#include "acppnode/common/target_address.hpp"
#include "acppnode/transport/internet/datagram_socket.hpp"
#include "acppnode/transport/link.hpp"
#include "acppnode/transport/link_error.hpp"

#include <asio/as_tuple.hpp>
#include <asio/experimental/awaitable_operators.hpp>
#include <asio/experimental/channel.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/this_coro.hpp>

#include <expected>

namespace acpp::proxy {

// Outbound-only endpoint preparation. A packet's target and payload remain
// owned by its logical write until DNS and socket I/O have both finished.
// The transport knows only the resulting IP endpoint, never DNS or routing.
inline net::awaitable<std::expected<udp::endpoint, ErrorCode>> ResolveUdpEndpoint(
    app::dns::DNS& dns,
    const TargetAddress& target,
    transport::internet::DatagramSocket& socket,
    const transport::internet::DatagramSocket::WriteOperation& write,
    net::io_context& io_context) {
    const auto parent_cancellation = co_await net::this_coro::cancellation_state;
    if (write.Cancelled()) co_return std::unexpected(write.CancellationReason());
    if (parent_cancellation.cancelled() != net::cancellation_type::none)
        co_return std::unexpected(ErrorCode::CANCELLED);
    if (!target.IsValid()) co_return std::unexpected(ErrorCode::INVALID_ARGUMENT);
    if (target.resolved_addr) {
        if (target.resolved_addr->is_v6() != socket.IsIPv6())
            co_return std::unexpected(ErrorCode::INVALID_ARGUMENT);
        co_return udp::endpoint(*target.resolved_addr, target.port);
    }
    if (!target.IsDomain()) co_return std::unexpected(ErrorCode::INVALID_ARGUMENT);

    struct CancellationWait {
        explicit CancellationWait(net::io_context& io) : wake(io, 1) {}
        net::experimental::channel<void(IoErrorCode)> wake;
        ErrorCode reason = ErrorCode::OK;
    } cancellation(io_context);
    transport::CancellationSubscription subscription(socket.Cancellation(),
        [](void* raw, transport::Cancellation event) noexcept {
            auto& wait = *static_cast<CancellationWait*>(raw);
            wait.reason = event.reason;
            wait.wake.close();
        }, &cancellation);
    if (cancellation.reason != ErrorCode::OK)
        co_return std::unexpected(cancellation.reason);

    // Both race participants return values even on cancellation: operator||
    // cancels and joins the loser before this scope releases borrowed state.
    auto resolve = [&]() -> net::awaitable<std::expected<udp::endpoint, ErrorCode>> {
        try {
            auto answer = co_await dns.Resolve(target.host);
            if (!answer.Ok()) co_return std::unexpected(answer.error);
            for (const auto& address : answer.addresses) {
                if (!address.is_unspecified() && address.is_v6() == socket.IsIPv6())
                    co_return udp::endpoint(address, target.port);
            }
            co_return std::unexpected(ErrorCode::DNS_NO_RECORD);
        } catch (const transport::LinkError& error) {
            co_return std::unexpected(error.code());
        } catch (const IoSystemError& error) {
            co_return std::unexpected(MapAsioError(error.code()));
        } catch (const std::bad_alloc&) {
            co_return std::unexpected(ErrorCode::RESOURCE_EXHAUSTED);
        } catch (...) {
            co_return std::unexpected(ErrorCode::INTERNAL);
        }
    };
    auto cancelled = [&]() -> net::awaitable<ErrorCode> {
        (void)co_await cancellation.wake.async_receive(net::as_tuple(net::use_awaitable));
        co_return cancellation.reason == ErrorCode::OK ? ErrorCode::CANCELLED : cancellation.reason;
    };
    using namespace net::experimental::awaitable_operators;
    try {
        auto result = co_await (resolve() || cancelled());
        if (write.Cancelled()) co_return std::unexpected(write.CancellationReason());
        if (cancellation.reason != ErrorCode::OK) co_return std::unexpected(cancellation.reason);
        if (parent_cancellation.cancelled() != net::cancellation_type::none)
            co_return std::unexpected(ErrorCode::CANCELLED);
        if (result.index() == 1) co_return std::unexpected(std::get<1>(result));
        co_return std::move(std::get<0>(result));
    } catch (const IoSystemError& error) {
        co_return std::unexpected(MapAsioError(error.code()));
    } catch (const std::bad_alloc&) {
        co_return std::unexpected(ErrorCode::RESOURCE_EXHAUSTED);
    } catch (...) {
        // Parent cancellation may abort both race participants before either
        // reports success. The race has still joined them before throwing.
        if (write.Cancelled()) co_return std::unexpected(write.CancellationReason());
        if (parent_cancellation.cancelled() != net::cancellation_type::none)
            co_return std::unexpected(ErrorCode::CANCELLED);
        co_return std::unexpected(ErrorCode::INTERNAL);
    }
}

}  // namespace acpp::proxy
