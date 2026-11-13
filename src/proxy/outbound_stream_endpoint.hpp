#pragma once

// 出站冷路径的下一跳与 streamSettings 准备，以及原生 UDP 出站的目标解析。
// 端点基类见 proxy/outbound_endpoint_base.hpp。

#include "app/dns/dns.hpp"
#include "app/relay.hpp"
#include "proxy/outbound_endpoint_base.hpp"
#include "common/target_address.hpp"
#include "infra/config_types.hpp"
#include "infra/log.hpp"
#include "transport/failure.hpp"
#include "transport/link.hpp"
#include "transport/datagram_socket.hpp"
#include "transport/outbound_target_builder.hpp"
#include "transport/stream_settings.hpp"
#include "transport/transport_security.hpp"
#include <asio/as_tuple.hpp>
#include <asio/experimental/awaitable_operators.hpp>
#include <asio/experimental/channel.hpp>
#include <asio/this_coro.hpp>
#include <asio/use_awaitable.hpp>

#include <cstdint>
#include <exception>
#include <optional>
#include <string>
#include <string_view>
#include <tl/expected.hpp>
#include <utility>

namespace proxy {

// Cold-path result for a proxy protocol with a next hop: the validated server
// and the Handler's sender settings (sendThrough is applied by proxyman).
struct PreparedNextHop {
    transport::OutboundServer server;
    transport::OutboundSenderSettings sender;
};

// The one application of a protocol's stream defaults (TLS requirement,
// fallback SNI, ALPN) to the source streamSettings. Without an explicit
// fallback server name the next hop's address is used.
[[nodiscard]] inline transport::StreamSettings PrepareOutboundStream(
    const infra::OutboundSourceConfig& source,
    const transport::OutboundServer& server,
    transport::OutboundStreamDefaults defaults) {
    if (defaults.fallback_server_name.empty()) {
        defaults.fallback_server_name = server.address;
    }
    auto settings = transport::NormalizeOutboundStreamSettings(source.stream_settings, defaults);
    transport::TransportSecurity::Prepare(settings, transport::StreamEndpointRole::Outbound);
    return settings;
}

[[nodiscard]] inline PreparedNextHop PrepareNextHop(
    const infra::OutboundSourceConfig& source,
    const transport::OutboundServer& server,
    const transport::OutboundStreamDefaults& defaults) {
    return PreparedNextHop{
        .server = server,
        .sender = {.stream_settings = PrepareOutboundStream(source, server, defaults),
                   .send_through = {}},
    };
}

inline void ApplyOutboundRelayTimeouts(
    transport::AsyncStream& stream,
    const app::RelayConfig& relay_config) {
    stream.SetIdleTimeout(relay_config.idle_timeout);
    stream.SetReadTimeout(std::chrono::seconds(0));
    stream.SetWriteTimeout(relay_config.write_timeout);
    stream.ClearPhaseDeadline();
}

inline void ApplyOutboundDatagramTimeouts(
    OutboundDatagramEndpointBase& endpoint,
    const app::RelayConfig& relay_config) {
    auto& socket = endpoint.RelayControl();
    socket.SetIdleTimeout(relay_config.idle_timeout);
    socket.SetWriteTimeout(relay_config.write_timeout);
}



// Outbound-only endpoint preparation. A packet's target and payload remain
// owned by its logical write until DNS and socket I/O have both finished.
// The transport knows only the resulting IP endpoint, never DNS or routing.
inline net::awaitable<tl::expected<udp::endpoint, common::ErrorCode>> ResolveUdpEndpoint(
    app::DNS& dns,
    const common::TargetAddress& target,
    transport::DatagramSocket& socket,
    const transport::DatagramSocket::WriteOperation& write) {
    const auto parent_cancellation = co_await net::this_coro::cancellation_state;
    if (write.Cancelled()) co_return tl::unexpected(write.CancellationReason());
    if (parent_cancellation.cancelled() != net::cancellation_type::none)
        co_return tl::unexpected(common::ErrorCode::CANCELLED);
    if (!target.IsValid()) co_return tl::unexpected(common::ErrorCode::INVALID_ARGUMENT);
    if (target.resolved_addr) {
        if (target.resolved_addr->is_v6() != socket.IsIPv6())
            co_return tl::unexpected(common::ErrorCode::INVALID_ARGUMENT);
        co_return udp::endpoint(*target.resolved_addr, target.port);
    }
    if (!target.IsDomain()) co_return tl::unexpected(common::ErrorCode::INVALID_ARGUMENT);

    struct CancellationWait final : transport::CancellationSubscription {
        explicit CancellationWait(net::any_io_executor executor)
            : wake(std::move(executor), 1) {}
        common::SignalChannel wake;
        common::ErrorCode reason = common::ErrorCode::OK;

    private:
        void OnCancellation(transport::Cancellation event) noexcept override {
            reason = event.reason;
            wake.close();
        }
    } cancellation(co_await net::this_coro::executor);
    cancellation.Resubscribe(socket.Cancellation());
    if (cancellation.reason != common::ErrorCode::OK)
        co_return tl::unexpected(cancellation.reason);

    // Both race participants return values even on cancellation: operator||
    // cancels and joins the loser before this scope releases borrowed state.
    auto resolve = [&]() -> net::awaitable<tl::expected<udp::endpoint, common::ErrorCode>> {
        try {
            auto answer = co_await dns.Resolve(target.host);
            if (!answer.Ok()) co_return tl::unexpected(answer.error);
            for (const auto& address : answer.addresses) {
                if (!address.is_unspecified() && address.is_v6() == socket.IsIPv6())
                    co_return udp::endpoint(address, target.port);
            }
            co_return tl::unexpected(common::ErrorCode::DNS_NO_RECORD);
        } catch (...) {
            co_return tl::unexpected(
                transport::ClassifyFailure(std::current_exception(), common::ErrorCode::INTERNAL));
        }
    };
    auto cancelled = [&]() -> net::awaitable<common::ErrorCode> {
        (void)co_await cancellation.wake.async_receive(net::as_tuple(net::use_awaitable));
        co_return cancellation.reason == common::ErrorCode::OK ? common::ErrorCode::CANCELLED : cancellation.reason;
    };
    using namespace net::experimental::awaitable_operators;
    try {
        auto result = co_await (resolve() || cancelled());
        if (write.Cancelled()) co_return tl::unexpected(write.CancellationReason());
        if (cancellation.reason != common::ErrorCode::OK) co_return tl::unexpected(cancellation.reason);
        if (parent_cancellation.cancelled() != net::cancellation_type::none)
            co_return tl::unexpected(common::ErrorCode::CANCELLED);
        if (result.index() == 1) co_return tl::unexpected(std::get<1>(result));
        co_return std::move(std::get<0>(result));
    } catch (...) {
        // 类型分类交给 ClassifyFailure；无法分类的异常可能来自父取消在任一
        // 参与者报告结果前中止竞争（竞争已先收束两者），按取消阶段解释。
        const auto failure =
            transport::ClassifyFailure(std::current_exception(), common::ErrorCode::INTERNAL);
        if (failure != common::ErrorCode::INTERNAL) co_return tl::unexpected(failure);
        if (write.Cancelled()) co_return tl::unexpected(write.CancellationReason());
        if (parent_cancellation.cancelled() != net::cancellation_type::none)
            co_return tl::unexpected(common::ErrorCode::CANCELLED);
        co_return tl::unexpected(common::ErrorCode::INTERNAL);
    }
}
}  // namespace proxy
