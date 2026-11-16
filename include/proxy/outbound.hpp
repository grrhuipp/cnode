#pragma once

#include "common/asio_types.hpp"
#include "app/relay.hpp"
#include "common/error.hpp"
#include "common/multi_buffer.hpp"
#include "common/session.hpp"
#include "infra/log.hpp"
#include "transport/link.hpp"
#include "transport/outbound_target_builder.hpp"

#include <asio/cancellation_state.hpp>
#include <asio/this_coro.hpp>
#include <exception>
#include <functional>
#include <optional>
#include <tuple>
#include <type_traits>
#include <utility>
#include <variant>
#include <tl/expected.hpp>

namespace infra {
struct TimeoutsConfig;
}

namespace proxy {

using OutboundProcessResult = tl::expected<app::RelayResult, common::ErrorCode>;

// Preparation cannot see the client link, payload, counters or relay callback.
struct OutboundPrepareContext {
    common::Context& ctx;
    transport::OutboundDialer& dialer;
    const infra::TimeoutsConfig& timeouts;
};

struct OutboundRejection {
    common::ErrorCode error;
    bool http_response = false;

    OutboundRejection(common::ErrorCode code, bool http = false) noexcept
        : error(code), http_response(http) {}
};

template <typename... Endpoints>
using OutboundPrepareResult = tl::expected<
    std::variant<std::reference_wrapper<Endpoints>...>, OutboundRejection>;

// Runtime TCP/native-UDP choices keep synchronous socket preparation inline.
// The asynchronous alternative is restricted to the same endpoint set.
template <typename... Endpoints>
using OutboundPreparationPlan = std::variant<
    OutboundPrepareResult<Endpoints...>, net::awaitable<OutboundPrepareResult<Endpoints...>>>;

// A session lives in the common coroutine frame; its endpoints may borrow it.
struct OutboundSession {
    OutboundSession() = default;
    OutboundSession(const OutboundSession&) = delete;
    OutboundSession& operator=(const OutboundSession&) = delete;
    OutboundSession(OutboundSession&&) = delete;
    OutboundSession& operator=(OutboundSession&&) = delete;
};

template <typename T>
struct OutboundPreparation {
    using Result = T;
    static constexpr bool asynchronous = false;
    static constexpr bool conditional = false;
};

template <typename T, typename Executor>
struct OutboundPreparation<net::awaitable<T, Executor>> {
    using Result = T;
    static constexpr bool asynchronous = true;
    static constexpr bool conditional = false;
};

template <typename T, typename Executor>
struct OutboundPreparation<std::variant<T, net::awaitable<T, Executor>>> {
    using Result = T;
    using Awaitable = net::awaitable<T, Executor>;
    static constexpr bool asynchronous = false;
    static constexpr bool conditional = true;
};

template <typename T>
inline constexpr bool kOutboundEndpointResult = false;

template <typename... Endpoints>
inline constexpr bool kOutboundEndpointResult<OutboundPrepareResult<Endpoints...>> = true;

template <typename Session, typename Arguments>
net::awaitable<OutboundProcessResult> ExecuteOutbound(
    Arguments arguments,
    common::Context& ctx,
    transport::Link inbound,
    transport::OutboundDialer& dialer,
    const infra::TimeoutsConfig& timeouts,
    app::StatsShard& stats,
    const app::RelayConfig& relay_config,
    common::MultiBufferBatch first_payload) {
    if (!inbound.Valid()) {
        co_return tl::unexpected(common::ErrorCode::PROTOCOL_DECODE_FAILED);
    }
    OutboundPrepareContext prepare_context{ctx, dialer, timeouts};
    Session session = std::apply([&](auto&&... args) {
        return Session(prepare_context, std::forward<decltype(args)>(args)...);
    }, std::move(arguments));
    static_assert(!std::is_move_constructible_v<Session> &&
                  !std::is_copy_constructible_v<Session>,
                  "outbound sessions must stay in the common coroutine frame");
    using Preparation = OutboundPreparation<decltype(session.Prepare())>;
    using Prepared = typename Preparation::Result;
    static_assert(kOutboundEndpointResult<Prepared> ||
                  std::is_same_v<Prepared, OutboundRejection>,
                  "Prepare must return typed endpoint references or an explicit rejection");
    static_assert(!std::is_same_v<Prepared, OutboundRejection> ||
                  (!Preparation::asynchronous && !Preparation::conditional),
                  "synchronous rejection preparation must not allocate a coroutine");

    OutboundProcessResult result = tl::unexpected(common::ErrorCode::INTERNAL);
    std::exception_ptr failure;
    try {
        std::optional<Prepared> prepared;
        if constexpr (Preparation::conditional) {
            auto preparation = session.Prepare();
            if (auto* ready = std::get_if<Prepared>(&preparation)) {
                prepared.emplace(std::move(*ready));
            } else {
                prepared.emplace(co_await std::move(
                    std::get<typename Preparation::Awaitable>(preparation)));
            }
        } else if constexpr (Preparation::asynchronous) {
            prepared.emplace(co_await session.Prepare());
        } else {
            prepared.emplace(session.Prepare());
        }
        std::optional<OutboundRejection> rejection;
        if constexpr (std::is_same_v<Prepared, OutboundRejection>) {
            rejection = *prepared;
        } else {
            if (!*prepared) {
                rejection = prepared->error();
            } else {
                result = co_await std::visit([&](auto endpoint) {
                    auto& target = endpoint.get();
                    auto& control = app::RelayControlOf(target);
                    if constexpr (requires { control.SetIdleTimeout(relay_config.idle_timeout); }) {
                        control.SetIdleTimeout(relay_config.idle_timeout);
                    }
                    if constexpr (requires { control.SetWriteTimeout(relay_config.write_timeout); }) {
                        control.SetWriteTimeout(relay_config.write_timeout);
                    }
                    app::ClearPhaseDeadlineIfSupported(target);
                    return app::DoRelayLink(
                        dialer.IoContext(), *inbound.reader, *inbound.writer, inbound.control,
                        target, ctx, stats, relay_config, std::move(first_payload));
                }, **prepared);
            }
        }
        if (rejection) {
            first_payload.clear();
            if (rejection->http_response && ctx.content.network == common::Network::TCP) {
                static constexpr char response[] =
                    "HTTP/1.1 403 Forbidden\r\n"
                    "Connection: close\r\n"
                    "Cache-Control: max-age=3600, public\r\n"
                    "Content-Length: 0\r\n\r\n";
                const net::const_buffer buffer(response, sizeof(response) - 1);
                try {
                    co_await inbound.writer->WriteBuffers({&buffer, 1});
                    co_await inbound.writer->AsyncShutdownWrite();
                } catch (...) {
                    LOG_CONN_DEBUG(ctx, "failed to write HTTP rejection response");
                    // A rejected connection stays rejected if its response fails.
                }
            }
            result = tl::unexpected(rejection->error);
        }
    } catch (...) {
        failure = std::current_exception();
    }
    if constexpr (requires { Session::reset_cancellation; }) {
        static_assert(Session::reset_cancellation);
        co_await net::this_coro::reset_cancellation_state(net::disable_cancellation());
    }
    if constexpr (requires { session.Finalize(result, failure); }) {
        try {
            session.Finalize(result, failure);
        } catch (...) {
            if (!failure) failure = std::current_exception();
        }
    }
    if (failure) std::rethrow_exception(failure);
    co_return result;
}

// The only request dispatch is cold-bound here. Protocols can prepare typed
// endpoints, never replace Process or supply an arbitrary processing callback.
class Outbound {
public:
    virtual ~Outbound() noexcept = default;
    Outbound(const Outbound&) = delete;
    Outbound& operator=(const Outbound&) = delete;
    Outbound(Outbound&&) = delete;
    Outbound& operator=(Outbound&&) = delete;

    virtual net::awaitable<OutboundProcessResult> Process(
        common::Context& ctx,
        transport::Link inbound,
        transport::OutboundDialer& dialer,
        const infra::TimeoutsConfig& timeouts,
        app::StatsShard& stats,
        const app::RelayConfig& relay_config,
        common::MultiBufferBatch first_payload) final {
        return process_(*this, ctx, inbound, dialer, timeouts, stats,
                        relay_config, std::move(first_payload));
    }

protected:
    template <typename Protocol>
    explicit Outbound(std::in_place_type_t<Protocol>) noexcept
        : process_(+[](Outbound& base, common::Context& ctx, transport::Link inbound,
                       transport::OutboundDialer& dialer, const infra::TimeoutsConfig& timeouts,
                       app::StatsShard& stats, const app::RelayConfig& relay_config,
                       common::MultiBufferBatch first_payload) {
            auto& protocol = static_cast<Protocol&>(base);
            return ExecuteOutbound<typename Protocol::Session>(
                protocol.SessionArguments(), ctx, inbound, dialer, timeouts, stats,
                relay_config, std::move(first_payload));
        }) {}

private:
    using ProcessEntry = net::awaitable<OutboundProcessResult> (*)(
        Outbound&, common::Context&, transport::Link, transport::OutboundDialer&,
        const infra::TimeoutsConfig&, app::StatsShard&, const app::RelayConfig&,
        common::MultiBufferBatch);
    ProcessEntry process_;
};

}  // namespace proxy

