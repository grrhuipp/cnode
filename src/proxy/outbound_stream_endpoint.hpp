#pragma once

// 出站冷路径的下一跳与 streamSettings 准备、Xray 风格单元素数组配置解析，
// 以及原生 UDP 出站的目标解析。端点基类见 proxy/outbound_endpoint_base.hpp。

#include "app/dns/dns.hpp"
#include "common/target_address.hpp"
#include "infra/config_types.hpp"
#include "infra/log.hpp"
#include "transport/failure.hpp"
#include "transport/link.hpp"
#include "transport/internet/datagram_socket.hpp"
#include "transport/internet/outbound_target_builder.hpp"
#include "transport/internet/stream_settings.hpp"
#include "transport/internet/transport_security.hpp"

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
        } catch (...) {
            co_return tl::unexpected(
                transport::ClassifyFailure(std::current_exception(), ErrorCode::INTERNAL));
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
    } catch (...) {
        // 类型分类交给 ClassifyFailure；无法分类的异常可能来自父取消在任一
        // 参与者报告结果前中止竞争（竞争已先收束两者），按取消阶段解释。
        const auto failure =
            transport::ClassifyFailure(std::current_exception(), ErrorCode::INTERNAL);
        if (failure != ErrorCode::INTERNAL) co_return tl::unexpected(failure);
        if (write.Cancelled()) co_return tl::unexpected(write.CancellationReason());
        if (parent_cancellation.cancelled() != net::cancellation_type::none)
            co_return tl::unexpected(ErrorCode::CANCELLED);
        co_return tl::unexpected(ErrorCode::INTERNAL);
    }
}
}  // namespace proxy
