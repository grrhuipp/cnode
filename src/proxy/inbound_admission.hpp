#pragma once

#include "common/error.hpp"
#include "proxy/handshake_errors.hpp"
#include "app/relay.hpp"
#include "app/inbound_handler.hpp"
#include "app/user_store.hpp"
#include "app/rate_limiter.hpp"
#include "app/stats.hpp"
#include "common/asio_types.hpp"
#include "common/session.hpp"
#include "app/user_online_tracker.hpp"
#include "common/target_address.hpp"
#include "infra/log.hpp"
#include "infra/config_types.hpp"
#include "transport/async_stream.hpp"
#include "transport/link.hpp"
#include "proxy/mux/mux_server.hpp"
#include "routing/dispatcher.hpp"

#include <cstdint>
#include <exception>
#include <memory>
#include <optional>
#include <span>
#include <string_view>
#include <tuple>
#include <vector>
#include <utility>
#include <type_traits>
#include <variant>
#include <tl/expected.hpp>

namespace proxy {
using app::AdmissionEnvironment;

struct InboundRequestTarget {
    common::Network network = common::Network::TCP;
    common::TargetAddress target;
    std::optional<common::ForwardedMetadata> forwarded = std::nullopt;
};

// Malformed requests can be rejected before an authenticated identity exists.
inline void LogInboundRequestRejected(const common::Context& ctx, std::string_view reason) {
    LOG_CONN_WARN(ctx, "request rejected from {}:{} > {}", ctx.inbound.source_ip, ctx.inbound.source_port, reason);
    LOG_ACCESS(common::FormatAccessLog(ctx, common::AccessStatus::Rejected, reason));
}

inline void LogInboundAuthFailure(const common::Context& ctx, std::string_view reason) {
    LOG_CONN_WARN(ctx, "authentication failed from {}:{} > {}", ctx.inbound.source_ip, ctx.inbound.source_port, reason);
    LOG_ACCESS(common::FormatAccessLog(ctx, common::AccessStatus::Rejected, reason));
}

inline void BindInboundRequestTarget(common::Context& ctx, InboundRequestTarget request) {
    if (request.forwarded) ctx.inbound.ApplyForwardedMetadata(*request.forwarded);
    ctx.content.network = request.network;
    ctx.outbound.original_target = {};
    ctx.outbound.target = std::move(request.target);
    ctx.outbound.route_target = {};
}

[[nodiscard]] inline std::optional<net::awaitable<app::ConnectionLimiter::Admission>>
ReserveInboundConnection(const AdmissionEnvironment& environment,
                         app::ConnectionLimiter::ReservationScope scope,
                         const common::Context& ctx) {
    return environment.limiter.TryReserve({
        .scope = scope, .family = ctx.inbound.connection_family,
        .tag = ctx.inbound.tag, .ip = ctx.inbound.source_ip,
        .check_ban = ctx.inbound.HasProxyProtocolClientIP()});
}

inline void RejectInboundAdmission(const common::Context& ctx, app::StatsShard& stats,
                                  app::ConnectionLimiter::RejectReason reason) {
    const auto* text = app::ConnectionLimiter::RejectReasonToString(reason);
    LOG_CONN_DEBUG(ctx, "connection rejected from {}:{} > {}",
                   ctx.inbound.source_ip, ctx.inbound.source_port, text);
    LOG_ACCESS(common::FormatAccessLog(ctx, common::AccessStatus::Rejected, text));
    stats.OnError();
}

[[nodiscard]] inline common::ErrorCode ClassifyInboundHandshakeException(
    std::exception_ptr failure,
    transport::AsyncStream* stream = nullptr,
    common::ErrorCode fallback = common::ErrorCode::INTERNAL) noexcept {
    try {
        std::rethrow_exception(failure);
    } catch (const app::WorkerMailboxFull&) {
        return common::ErrorCode::RESOURCE_EXHAUSTED;
    } catch (const std::bad_alloc&) {
        return common::ErrorCode::RESOURCE_EXHAUSTED;
    } catch (const IoSystemError& error) {
        return stream
            ? ClassifyHandshakeReadException(*stream, error)
            : common::MapAsioError(error.code());
    } catch (...) {
        return transport::ClassifyFailure(failure, fallback);
    }
}

// A keyed credential exists before lookup. Trial-decryption protocols deliberately
// have no credential key: random SS salts and VMess AuthIDs never enter its ban table.
enum class KeyedInboundProtocol : uint8_t { Trojan, Vless, AnyTls, Hysteria };
struct KeyedInboundCredential {
    KeyedInboundProtocol protocol;
    std::span<const uint8_t> raw;
};

struct InboundContext {
    const AdmissionEnvironment& admission;
    routing::Dispatcher& dispatcher;
    InboundSettings settings;
    net::io_context& io_context;
    common::Context& session;
    const infra::TimeoutsConfig& timeouts;
    uint32_t pressure_idle_timeout;
};

struct AnyTlsInboundSession;
struct HysteriaInboundSession;
struct MultiplexedInboundSession;

class MuxSessionPlan {
public:
    transport::Link link;
    transport::AsyncStream& control;
    MuxAllowedNetwork allowed_network;
private:
    friend struct MultiplexedInboundSession;
    MuxSessionPlan(transport::Link endpoints, transport::AsyncStream& stream,
                   MuxAllowedNetwork allowed) noexcept
        : link(endpoints), control(stream), allowed_network(allowed) {}
};

// Only a session explicitly supporting a physical Mux loop can prepare it.
struct MultiplexedInboundSession {
protected:
    static MuxSessionPlan MuxPlan(transport::Link link,
        transport::AsyncStream& control, MuxAllowedNetwork allowed) noexcept {
        return MuxSessionPlan(link, control, allowed);
    }
};

class AnyTlsSessionLoop {
public:
    using State = AnyTlsInboundSession;
    net::awaitable<app::RelayResult> Run();
private:
    friend struct AnyTlsInboundSession;
    explicit AnyTlsSessionLoop(AnyTlsInboundSession& session) noexcept : session_(session) {}
    AnyTlsInboundSession& session_;
};

struct InboundPeerClosed {};
using InboundPrepared = tl::expected<routing::DispatchRequest, common::ErrorCode>;
using MultiplexedInboundPrepared = tl::expected<
    std::variant<routing::DispatchRequest, MuxSessionPlan, InboundPeerClosed>, common::ErrorCode>;
using AnyTlsInboundPrepared = tl::expected<AnyTlsSessionLoop, common::ErrorCode>;

template <typename T> struct InboundPreparation {
    using Result = T;
    static constexpr bool asynchronous = false;
};
template <typename T, typename Executor>
struct InboundPreparation<net::awaitable<T, Executor>> {
    using Result = T;
    static constexpr bool asynchronous = true;
};

template <typename ProtocolSession, typename... Arguments>
net::awaitable<app::RelayResult> ProcessInbound(
    std::unique_ptr<transport::AsyncStream> stream,
    InboundContext context,
    Arguments... arguments);

struct NativeAssociationAdmission;

class AuthenticatedInbound;
class InboundAuthentication {
public:
    InboundAuthentication(InboundAuthentication&&) noexcept = default;
    InboundAuthentication(const InboundAuthentication&) = delete;
    [[nodiscard]] net::awaitable<common::ErrorCode> VerifyCredential(KeyedInboundCredential credential) {
        using app::UserProtocol;
        const auto protocol = [](KeyedInboundProtocol value) {
            switch (value) {
            case KeyedInboundProtocol::Trojan: return UserProtocol::Trojan;
            case KeyedInboundProtocol::Vless: return UserProtocol::Vless;
            case KeyedInboundProtocol::AnyTls: return UserProtocol::AnyTls;
            case KeyedInboundProtocol::Hysteria: return UserProtocol::Hysteria;
            }
            std::terminate();
        }(credential.protocol);
        const auto revision = app::UserStore::CredentialRevision(protocol, ctx_->inbound.tag);
        credential_ = environment_->limiter.FingerprintCredential(ctx_->inbound.tag, credential.raw, revision);
        // The lazy operation owns the fingerprint, never the caller's raw bytes
        // or this movable phase value.
        return CheckCredentialAdmission(*environment_, *ctx_, *credential_, protocol, revision);
    }
    [[nodiscard]] net::awaitable<common::ErrorCode> RejectCredential(std::string_view reason) {
        return RecordFailure(*environment_, *ctx_, reason, credential_, common::ErrorCode::PROTOCOL_AUTH_FAILED);
    }
    [[nodiscard]] AuthenticatedInbound Bind(const common::UserProfile& profile,
                                           std::optional<InboundRequestTarget> request) &&;
private:
    friend net::awaitable<tl::expected<InboundAuthentication, common::ErrorCode>>
    BeginInboundAuthentication(const AdmissionEnvironment&, common::Context&);
    InboundAuthentication(const AdmissionEnvironment& environment, common::Context& ctx) noexcept
        : environment_(&environment), ctx_(&ctx) {}
    static net::awaitable<common::ErrorCode> CheckCredentialAdmission(
        const AdmissionEnvironment& environment, common::Context& ctx,
        app::AuthCredentialKey credential, app::UserProtocol protocol, uint64_t revision) {
        try {
            const auto reason = co_await environment.limiter.CheckCredential(credential);
            if (app::UserStore::CredentialRevision(protocol, ctx.inbound.tag) != revision ||
                reason == app::ConnectionLimiter::RejectReason::NONE) co_return common::ErrorCode::OK;
            co_return co_await RecordFailure(environment, ctx,
                app::ConnectionLimiter::RejectReasonToString(reason), std::nullopt,
                reason == app::ConnectionLimiter::RejectReason::TRACKING_CAPACITY
                    ? common::ErrorCode::RESOURCE_EXHAUSTED : common::ErrorCode::BLOCKED);
        } catch (...) {
            co_return ClassifyInboundHandshakeException(std::current_exception());
        }
    }
    static net::awaitable<common::ErrorCode> RecordFailure(
        const AdmissionEnvironment& environment, common::Context& ctx, std::string_view reason,
        std::optional<app::AuthCredentialKey> credential, common::ErrorCode error) {
        LogInboundAuthFailure(ctx, reason);
        reason = {};
        const bool track_ip = environment.limiter.TracksAuthBan() && ctx.inbound.HasProxyProtocolClientIP();
        if (track_ip || credential) {
            try {
                co_await environment.limiter.OnAuthFailTracked(ctx.inbound.tag,
                    track_ip ? std::string_view(ctx.inbound.source_ip) : std::string_view{}, credential);
            } catch (const app::WorkerMailboxFull&) {
                LOG_CONN_WARN(ctx, "authentication failure tracking unavailable > mailbox full");
            } catch (const IoSystemError&) {
                LOG_CONN_WARN(ctx, "authentication failure tracking unavailable > coordinator I/O error");
            }
        }
        co_return error;
    }
    const AdmissionEnvironment* environment_;
    common::Context* ctx_;
    std::optional<app::AuthCredentialKey> credential_;
};

class AuthenticatedInbound {
public:
    AuthenticatedInbound(AuthenticatedInbound&&) noexcept = default;
    AuthenticatedInbound(const AuthenticatedInbound&) = delete;
    [[nodiscard]] common::ErrorCode Reject(std::string_view reason, common::ErrorCode error) && {
        LogInboundRequestRejected(*ctx_, reason);
        return error;
    }
private:
    template <typename ProtocolSession, typename... Arguments>
    friend net::awaitable<app::RelayResult> ProcessInbound(
        std::unique_ptr<transport::AsyncStream>, InboundContext, Arguments...);
    friend class transport::HysteriaConnection;
    friend struct NativeAssociationAdmission;
    [[nodiscard]] net::awaitable<tl::expected<app::UserOnlineSessionGuard, common::ErrorCode>> Admit() && {
        return AdmitSession(*environment_, *ctx_, user_id_, device_limit_);
    }
    friend class InboundAuthentication;
    AuthenticatedInbound(const AdmissionEnvironment& environment, common::Context& ctx,
                         const common::UserProfile& profile) noexcept
        : environment_(&environment), ctx_(&ctx), user_id_(profile.user_id), device_limit_(profile.device_limit) {}
    static net::awaitable<tl::expected<app::UserOnlineSessionGuard, common::ErrorCode>> AdmitSession(
        const AdmissionEnvironment& environment, common::Context& ctx,
        int64_t user_id, uint32_t device_limit) {
        try {
            auto session = co_await environment.online_users.TryConnectSession(
                ctx.inbound.tag, user_id, ctx.inbound.source_ip, device_limit);
            if (!session) {
                LOG_CONN_DEBUG(ctx, "User {} exceeded device limit ({})", user_id, device_limit);
                LOG_ACCESS(common::FormatAccessLog(ctx, common::AccessStatus::Rejected, "device limit"));
                co_return tl::unexpected(common::ErrorCode::PERMISSION_DENIED);
            }
            LOG_CONN_DEBUG(ctx, "authentication succeeded from {}:{}", ctx.inbound.source_ip, ctx.inbound.source_port);
            co_return std::move(*session);
        } catch (...) {
            co_return tl::unexpected(ClassifyInboundHandshakeException(std::current_exception()));
        }
    }
    const AdmissionEnvironment* environment_;
    common::Context* ctx_;
    int64_t user_id_;
    uint32_t device_limit_;
};

inline AuthenticatedInbound InboundAuthentication::Bind(
    const common::UserProfile& profile, std::optional<InboundRequestTarget> request) && {
    ctx_->inbound.user_id = profile.user_id;
    ctx_->inbound.user_email = profile.email;
    ctx_->content.speed_limit = profile.speed_limit;
    if (request) BindInboundRequestTarget(*ctx_, std::move(*request));
    return AuthenticatedInbound(*environment_, *ctx_, profile);
}

[[nodiscard]] inline net::awaitable<tl::expected<InboundAuthentication, common::ErrorCode>>
BeginInboundAuthentication(const AdmissionEnvironment& environment, common::Context& ctx) {
    ctx.inbound.user_id = 0;
    ctx.inbound.user_email.clear();
    try {
    if (environment.limiter.TracksAuthBan() && ctx.inbound.HasProxyProtocolClientIP() &&
        co_await environment.limiter.IsBanned(ctx.inbound.tag, ctx.inbound.source_ip)) {
        LOG_ACCESS(common::FormatAccessLog(ctx, common::AccessStatus::Rejected, "IP banned"));
        co_return tl::unexpected(common::ErrorCode::BLOCKED);
    }
    co_return InboundAuthentication(environment, ctx);
    } catch (...) {
        co_return tl::unexpected(ClassifyInboundHandshakeException(std::current_exception()));
    }
}

struct NativeAssociationAdmission {
    app::ConnectionLimiter::Reservation connection;
    app::ConnectionLimiter::Reservation ip;
    app::UserOnlineSessionGuard user_session;
private:
    friend class app::UdpIngress;
    [[nodiscard]] static net::awaitable<std::optional<NativeAssociationAdmission>>
    Admit(const AdmissionEnvironment&, common::Context&, AuthenticatedInbound);
};
[[nodiscard]] inline net::awaitable<std::optional<NativeAssociationAdmission>>
NativeAssociationAdmission::Admit(const AdmissionEnvironment& environment, common::Context& ctx,
                       AuthenticatedInbound bound) {
    NativeAssociationAdmission admitted;
    for (auto scope : {app::ConnectionLimiter::ReservationScope::Physical, app::ConnectionLimiter::ReservationScope::ClientIp}) {
        if (auto pending = ReserveInboundConnection(environment, scope, ctx)) {
            auto admission = co_await std::move(*pending);
            if (admission.reason != app::ConnectionLimiter::RejectReason::NONE) {
                RejectInboundAdmission(ctx, environment.stats, admission.reason);
                co_return std::nullopt;
            }
            (scope == app::ConnectionLimiter::ReservationScope::Physical ? admitted.connection : admitted.ip) = std::move(admission.reservation);
        }
    }
    auto session = co_await std::move(bound).Admit();
    if (!session) {
        if (session.error() != common::ErrorCode::CANCELLED && session.error() != common::ErrorCode::SOCKET_EOF)
            environment.stats.OnError();
        co_return std::nullopt;
    }
    admitted.user_session = std::move(*session);
    co_return std::move(admitted);
}

class InboundSubstreamAdmission {
public:
    explicit InboundSubstreamAdmission(app::StatsShard& stats) noexcept : connection_stats_(stats) {}
    // Reserves the logical-stream slot. Empty when the limiter tracks nothing
    // for it; otherwise the caller awaits the result and passes it to Hold.
    [[nodiscard]] static std::optional<net::awaitable<app::ConnectionLimiter::Admission>>
    Reserve(const AdmissionEnvironment& environment, const common::Context& ctx) {
        return ReserveInboundConnection(
            environment, app::ConnectionLimiter::ReservationScope::Logical, ctx);
    }
    [[nodiscard]] bool Hold(app::ConnectionLimiter::Admission admission, const common::Context& ctx, app::StatsShard& stats) {
        if (admission.reason != app::ConnectionLimiter::RejectReason::NONE) {
            RejectInboundAdmission(ctx, stats, admission.reason);
            return false;
        }
        reservation_ = std::move(admission.reservation);
        return true;
    }
private:
    app::ConnectionStatsScope connection_stats_;
    app::ConnectionLimiter::Reservation reservation_;
};

[[nodiscard]] inline common::UserProfile MakeUserProfile(const infra::InboundUserSpec& spec) {
    common::UserProfile profile;
    profile.email = spec.email;
    profile.user_id = spec.user_id;
    profile.speed_limit = spec.speed_limit;
    profile.device_limit = spec.device_limit;
    return profile;
}

[[nodiscard]] inline app::RelayResult RejectInbound(app::StatsShard& stats, transport::AsyncStream* stream, common::ErrorCode error) noexcept {
    if (stream) stream->CloseAbortive();
    if (error != common::ErrorCode::CANCELLED && error != common::ErrorCode::SOCKET_EOF) stats.OnError();
    app::RelayResult result;
    result.error = error;
    return result;
}

// Protocol state and all borrowing wrappers remain at their final address until
// the dispatcher or the explicitly permitted physical-session loop has joined.
template <typename ProtocolSession, typename... Arguments>
net::awaitable<app::RelayResult> ProcessInbound(
    std::unique_ptr<transport::AsyncStream> stream,
    InboundContext context,
    Arguments... arguments) {
    auto& stats = context.admission.stats;
    if (!stream) {
        co_return RejectInbound(stats, nullptr, common::ErrorCode::PROTOCOL_DECODE_FAILED);
    }
    try {
        ProtocolSession protocol{std::move(arguments)...};
        static_assert(!std::is_move_constructible_v<ProtocolSession> &&
                      !std::is_copy_constructible_v<ProtocolSession>,
                      "inbound session state must stay in the common coroutine frame");
        app::UserOnlineSessionGuard user_session;
        // Hysteria's physical connection already owns authentication and the
        // device lease. Logical streams must not reserve the device again.
        if constexpr (!std::is_same_v<ProtocolSession, HysteriaInboundSession>) {
            auto authentication = co_await BeginInboundAuthentication(
                context.admission, context.session);
            if (!authentication)
                co_return RejectInbound(stats, stream.get(), authentication.error());
            auto authenticated = co_await protocol.Authenticate(
                *stream, std::move(*authentication), context);
            if (!authenticated)
                co_return RejectInbound(stats, stream.get(), authenticated.error());
            auto admitted = co_await std::move(*authenticated).Admit();
            if (!admitted)
                co_return RejectInbound(stats, stream.get(), admitted.error());
            user_session = std::move(*admitted);
        }
        using Preparation = InboundPreparation<decltype(protocol.Prepare(stream, context))>;
        using Prepared = typename Preparation::Result;
        static_assert(std::is_same_v<Prepared, InboundPrepared> ||
                      std::is_same_v<Prepared, MultiplexedInboundPrepared> ||
                      std::is_same_v<Prepared, AnyTlsInboundPrepared>,
                      "inbound Prepare must return its typed dispatch/session plan");
        static_assert(!std::is_same_v<Prepared, MultiplexedInboundPrepared> ||
                      std::is_base_of_v<MultiplexedInboundSession, ProtocolSession>,
                      "ordinary inbound sessions cannot return a physical Mux loop");
        std::optional<Prepared> prepared;
        if constexpr (Preparation::asynchronous) {
            prepared.emplace(co_await protocol.Prepare(stream, context));
        } else {
            prepared.emplace(protocol.Prepare(stream, context));
        }
        if (!*prepared)
            co_return RejectInbound(stats, stream.get(), prepared->error());
        if constexpr (std::is_same_v<Prepared, AnyTlsInboundPrepared>) {
            static_assert(std::is_same_v<ProtocolSession, typename Prepared::value_type::State>,
                          "only the typed loop's own state can prepare its execution");
            co_return co_await (**prepared).Run();
        } else {
            if constexpr (std::is_same_v<Prepared, MultiplexedInboundPrepared>) {
                if (std::holds_alternative<InboundPeerClosed>(**prepared))
                    co_return app::RelayResult{};
                if (auto* mux = std::get_if<MuxSessionPlan>(&**prepared)) {
                    co_return co_await ServeMuxInbound(
                        context.io_context, mux->link, mux->control, context.dispatcher,
                        context.settings.dispatch_policy, context.admission, context.session,
                        stats, context.timeouts, context.pressure_idle_timeout, mux->allowed_network);
                }
            }
            auto& request = [&]() -> routing::DispatchRequest& {
                if constexpr (std::is_same_v<Prepared, MultiplexedInboundPrepared>)
                    return std::get<routing::DispatchRequest>(**prepared);
                else
                    return **prepared;
            }();
            co_return co_await DispatchAuthenticatedInbound(context.dispatcher,
                context.io_context, context.settings.dispatch_policy,
                std::move(request), context.session, stats, context.timeouts);
        }
    } catch (...) {
        co_return RejectInbound(
            stats, stream.get(),
            ClassifyInboundHandshakeException(std::current_exception()));
    }
}

template <typename Protocol>
net::awaitable<app::RelayResult> Inbound::Execute(
    Inbound& inbound, std::unique_ptr<transport::AsyncStream> stream,
    routing::Dispatcher& dispatcher, InboundSettings settings,
    net::io_context& io_context, common::Context& ctx,
    const infra::TimeoutsConfig& timeouts, uint32_t pressure_idle_timeout) {
    auto& protocol = static_cast<Protocol&>(inbound);
    return std::apply([&](auto&&... arguments) {
        return ProcessInbound<typename Protocol::Session>(
            std::move(stream),
            InboundContext{protocol.Environment(), dispatcher, settings, io_context,
                           ctx, timeouts, pressure_idle_timeout},
            std::forward<decltype(arguments)>(arguments)...);
    }, protocol.SessionArguments());
}

template <typename PreparedUser, typename AssignCredential>
[[nodiscard]] std::optional<::app::UserSet>
BuildHashedInboundUsers(std::string_view protocol_name, const ::app::BuildRequest& req,
                        std::span<const ::infra::InboundUserSpec> specs, AssignCredential&& assign_credential) {
    std::vector<PreparedUser> users;
    users.reserve(specs.size());
    for (const auto& spec : specs) {
        if (spec.credential.empty()) {
            LOG_WARN("{} inbound '{}': user credential is empty", protocol_name, req.tag);
            return std::nullopt;
        }
        PreparedUser user;
        assign_credential(user, spec.credential);
        user.profile = MakeUserProfile(spec);
        users.push_back(std::move(user));
    }
    return ::app::UserSet{std::move(users)};
}
} // namespace proxy
