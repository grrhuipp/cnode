#pragma once

#include "common/error.hpp"
#include "app/relay.hpp"
#include "app/proxyman/inbound/handler.hpp"
#include "app/proxyman/inbound/user_store.hpp"
#include "app/rate_limiter.hpp"
#include "app/stats.hpp"
#include "common/asio_types.hpp"
#include "common/session.hpp"
#include "common/sharded_user_stats.hpp"
#include "common/target_address.hpp"
#include "infra/log.hpp"
#include "infra/config_types.hpp"
#include "transport/async_stream.hpp"
#include "transport/failure.hpp"

#include <cstdint>
#include <exception>
#include <memory>
#include <optional>
#include <span>
#include <string_view>
#include <vector>
#include <utility>
#include <tl/expected.hpp>

namespace proxy {
using proxyman::inbound::AdmissionEnvironment;

struct InboundRequestTarget {
    Network network = Network::TCP;
    TargetAddress target;
    std::optional<ForwardedMetadata> forwarded = std::nullopt;
};

// Malformed requests can be rejected before an authenticated identity exists.
inline void LogInboundRequestRejected(const session::Context& ctx, std::string_view reason) {
    LOG_CONN_WARN(ctx, "request rejected from {}:{} > {}", ctx.inbound.source_ip, ctx.inbound.source_port, reason);
    LOG_ACCESS(FormatAccessLog(ctx, AccessStatus::Rejected, reason));
}

inline void LogInboundAuthFailure(const session::Context& ctx, std::string_view reason) {
    LOG_CONN_WARN(ctx, "authentication failed from {}:{} > {}", ctx.inbound.source_ip, ctx.inbound.source_port, reason);
    LOG_ACCESS(FormatAccessLog(ctx, AccessStatus::Rejected, reason));
}

inline void BindInboundRequestTarget(session::Context& ctx, InboundRequestTarget request) {
    if (request.forwarded) ctx.inbound.ApplyForwardedMetadata(*request.forwarded);
    ctx.content.network = request.network;
    ctx.outbound.original_target = {};
    ctx.outbound.target = std::move(request.target);
    ctx.outbound.route_target = {};
}

[[nodiscard]] inline std::optional<net::awaitable<ConnectionLimiter::Admission>>
ReserveInboundConnection(const AdmissionEnvironment& environment,
                         ConnectionLimiter::ReservationScope scope,
                         const session::Context& ctx) {
    return environment.limiter.TryReserve({
        .scope = scope, .family = ctx.inbound.connection_family,
        .tag = ctx.inbound.tag, .ip = ctx.inbound.source_ip,
        .check_ban = ctx.inbound.HasProxyProtocolClientIP()});
}

inline void RejectInboundAdmission(const session::Context& ctx, StatsShard& stats,
                                  ConnectionLimiter::RejectReason reason) {
    const auto* text = ConnectionLimiter::RejectReasonToString(reason);
    LOG_CONN_DEBUG(ctx, "connection rejected from {}:{} > {}",
                   ctx.inbound.source_ip, ctx.inbound.source_port, text);
    LOG_ACCESS(FormatAccessLog(ctx, AccessStatus::Rejected, text));
    stats.OnError();
}

// A keyed credential exists before lookup. Trial-decryption protocols deliberately
// have no credential key: random SS salts and VMess AuthIDs never enter its ban table.
enum class KeyedInboundProtocol : uint8_t { Trojan, Vless, AnyTls, Hysteria };
struct KeyedInboundCredential {
    KeyedInboundProtocol protocol;
    std::span<const uint8_t> raw;
};

class AuthenticatedInbound;
class InboundAuthentication {
public:
    InboundAuthentication(InboundAuthentication&&) noexcept = default;
    InboundAuthentication(const InboundAuthentication&) = delete;
    [[nodiscard]] net::awaitable<ErrorCode> VerifyCredential(KeyedInboundCredential credential) {
        using proxyman::inbound::UserProtocol;
        const auto protocol = [](KeyedInboundProtocol value) {
            switch (value) {
            case KeyedInboundProtocol::Trojan: return UserProtocol::Trojan;
            case KeyedInboundProtocol::Vless: return UserProtocol::Vless;
            case KeyedInboundProtocol::AnyTls: return UserProtocol::AnyTls;
            case KeyedInboundProtocol::Hysteria: return UserProtocol::Hysteria;
            }
            std::terminate();
        }(credential.protocol);
        const auto revision = proxyman::inbound::UserStore::CredentialRevision(protocol, ctx_->inbound.tag);
        credential_ = environment_->limiter.FingerprintCredential(ctx_->inbound.tag, credential.raw, revision);
        // The lazy operation owns the fingerprint, never the caller's raw bytes
        // or this movable phase value.
        return CheckCredentialAdmission(*environment_, *ctx_, *credential_, protocol, revision);
    }
    [[nodiscard]] net::awaitable<ErrorCode> RejectCredential(std::string_view reason) {
        return RecordFailure(*environment_, *ctx_, reason, credential_, ErrorCode::PROTOCOL_AUTH_FAILED);
    }
    [[nodiscard]] AuthenticatedInbound Bind(const UserProfile& profile,
                                           std::optional<InboundRequestTarget> request) &&;
private:
    friend net::awaitable<tl::expected<InboundAuthentication, ErrorCode>>
    BeginInboundAuthentication(const AdmissionEnvironment&, session::Context&);
    InboundAuthentication(const AdmissionEnvironment& environment, session::Context& ctx) noexcept
        : environment_(&environment), ctx_(&ctx) {}
    static net::awaitable<ErrorCode> CheckCredentialAdmission(
        const AdmissionEnvironment& environment, session::Context& ctx,
        AuthCredentialKey credential, proxyman::inbound::UserProtocol protocol, uint64_t revision) {
        try {
            const auto reason = co_await environment.limiter.CheckCredential(credential);
            if (proxyman::inbound::UserStore::CredentialRevision(protocol, ctx.inbound.tag) != revision ||
                reason == ConnectionLimiter::RejectReason::NONE) co_return ErrorCode::OK;
            co_return co_await RecordFailure(environment, ctx,
                ConnectionLimiter::RejectReasonToString(reason), std::nullopt,
                reason == ConnectionLimiter::RejectReason::TRACKING_CAPACITY
                    ? ErrorCode::RESOURCE_EXHAUSTED : ErrorCode::BLOCKED);
        } catch (const WorkerMailboxFull&) {
            co_return ErrorCode::RESOURCE_EXHAUSTED;
        } catch (...) {
            co_return transport::ClassifyFailure(std::current_exception(), ErrorCode::INTERNAL);
        }
    }
    static net::awaitable<ErrorCode> RecordFailure(
        const AdmissionEnvironment& environment, session::Context& ctx, std::string_view reason,
        std::optional<AuthCredentialKey> credential, ErrorCode error) {
        LogInboundAuthFailure(ctx, reason);
        reason = {};
        const bool track_ip = environment.limiter.TracksAuthBan() && ctx.inbound.HasProxyProtocolClientIP();
        if (track_ip || credential) {
            try {
                co_await environment.limiter.OnAuthFailTracked(ctx.inbound.tag,
                    track_ip ? std::string_view(ctx.inbound.source_ip) : std::string_view{}, credential);
            } catch (const WorkerMailboxFull&) {
                LOG_CONN_WARN(ctx, "authentication failure tracking unavailable > mailbox full");
            } catch (const IoSystemError&) {
                LOG_CONN_WARN(ctx, "authentication failure tracking unavailable > coordinator I/O error");
            }
        }
        co_return error;
    }
    const AdmissionEnvironment* environment_;
    session::Context* ctx_;
    std::optional<AuthCredentialKey> credential_;
};

class AuthenticatedInbound {
public:
    AuthenticatedInbound(AuthenticatedInbound&&) noexcept = default;
    AuthenticatedInbound(const AuthenticatedInbound&) = delete;
    [[nodiscard]] ErrorCode Reject(std::string_view reason, ErrorCode error) && {
        LOG_CONN_WARN(*ctx_, "request rejected from {}:{} > {}", ctx_->inbound.source_ip, ctx_->inbound.source_port, reason);
        LOG_ACCESS(FormatAccessLog(*ctx_, AccessStatus::Rejected, reason));
        return error;
    }
    [[nodiscard]] net::awaitable<tl::expected<UserOnlineSessionGuard, ErrorCode>> Admit() && {
        return AdmitSession(*environment_, *ctx_, user_id_, device_limit_);
    }
private:
    friend class InboundAuthentication;
    AuthenticatedInbound(const AdmissionEnvironment& environment, session::Context& ctx,
                         const UserProfile& profile) noexcept
        : environment_(&environment), ctx_(&ctx), user_id_(profile.user_id), device_limit_(profile.device_limit) {}
    static net::awaitable<tl::expected<UserOnlineSessionGuard, ErrorCode>> AdmitSession(
        const AdmissionEnvironment& environment, session::Context& ctx,
        int64_t user_id, uint32_t device_limit) {
        try {
            auto session = co_await environment.online_users.TryConnectSession(
                ctx.inbound.tag, user_id, ctx.inbound.source_ip, device_limit);
            if (!session) {
                LOG_CONN_DEBUG(ctx, "User {} exceeded device limit ({}/{})", user_id,
                    environment.online_users.OnlineDeviceCount(
                        ctx.inbound.tag, static_cast<uint64_t>(user_id)), device_limit);
                LOG_ACCESS(FormatAccessLog(ctx, AccessStatus::Rejected, "device limit"));
                co_return tl::unexpected(ErrorCode::PERMISSION_DENIED);
            }
            LOG_CONN_DEBUG(ctx, "authentication succeeded from {}:{}", ctx.inbound.source_ip, ctx.inbound.source_port);
            co_return std::move(*session);
        } catch (const WorkerMailboxFull&) {
            co_return tl::unexpected(ErrorCode::RESOURCE_EXHAUSTED);
        } catch (...) {
            co_return tl::unexpected(transport::ClassifyFailure(std::current_exception(), ErrorCode::INTERNAL));
        }
    }
    const AdmissionEnvironment* environment_;
    session::Context* ctx_;
    int64_t user_id_;
    uint32_t device_limit_;
};

inline AuthenticatedInbound InboundAuthentication::Bind(
    const UserProfile& profile, std::optional<InboundRequestTarget> request) && {
    ctx_->inbound.user_id = profile.user_id;
    ctx_->inbound.user_email = profile.email;
    ctx_->content.speed_limit = profile.speed_limit;
    if (request) BindInboundRequestTarget(*ctx_, std::move(*request));
    return AuthenticatedInbound(*environment_, *ctx_, profile);
}

[[nodiscard]] inline net::awaitable<tl::expected<InboundAuthentication, ErrorCode>>
BeginInboundAuthentication(const AdmissionEnvironment& environment, session::Context& ctx) {
    ctx.inbound.user_id = 0;
    ctx.inbound.user_email.clear();
    try {
    if (environment.limiter.TracksAuthBan() && ctx.inbound.HasProxyProtocolClientIP() &&
        co_await environment.limiter.IsBanned(ctx.inbound.tag, ctx.inbound.source_ip)) {
        LOG_ACCESS(FormatAccessLog(ctx, AccessStatus::Rejected, "IP banned"));
        co_return tl::unexpected(ErrorCode::BLOCKED);
    }
    co_return InboundAuthentication(environment, ctx);
    } catch (const WorkerMailboxFull&) {
        co_return tl::unexpected(ErrorCode::RESOURCE_EXHAUSTED);
    } catch (...) {
        co_return tl::unexpected(transport::ClassifyFailure(std::current_exception(), ErrorCode::INTERNAL));
    }
}

[[nodiscard]] inline net::awaitable<tl::expected<UserOnlineSessionGuard, ErrorCode>>
AuthenticateAndAdmit(InboundAuthentication authentication, const UserProfile* matched,
                     std::string_view mismatch_reason, std::optional<InboundRequestTarget> request) {
    if (!matched) {
        auto rejection = authentication.RejectCredential(mismatch_reason);
        mismatch_reason = {};
        request.reset();
        co_return tl::unexpected(co_await std::move(rejection));
    }
    auto bound = std::move(authentication).Bind(*matched, std::move(request));
    matched = nullptr;
    mismatch_reason = {};
    request.reset();
    co_return co_await std::move(bound).Admit();
}

struct NativeAssociationAdmission {
    ConnectionLimiter::Reservation connection;
    ConnectionLimiter::Reservation ip;
    UserOnlineSessionGuard user_session;
};
[[nodiscard]] inline net::awaitable<std::optional<NativeAssociationAdmission>>
AdmitNativeAssociation(const AdmissionEnvironment& environment, session::Context& ctx,
                       AuthenticatedInbound bound) {
    NativeAssociationAdmission admitted;
    for (auto scope : {ConnectionLimiter::ReservationScope::Physical, ConnectionLimiter::ReservationScope::ClientIp}) {
        if (auto pending = ReserveInboundConnection(environment, scope, ctx)) {
            auto admission = co_await std::move(*pending);
            if (admission.reason != ConnectionLimiter::RejectReason::NONE) {
                RejectInboundAdmission(ctx, environment.stats, admission.reason);
                co_return std::nullopt;
            }
            (scope == ConnectionLimiter::ReservationScope::Physical ? admitted.connection : admitted.ip) = std::move(admission.reservation);
        }
    }
    auto session = co_await std::move(bound).Admit();
    if (!session) {
        if (session.error() != ErrorCode::CANCELLED && session.error() != ErrorCode::SOCKET_EOF)
            environment.stats.OnError();
        co_return std::nullopt;
    }
    admitted.user_session = std::move(*session);
    co_return std::move(admitted);
}

class InboundSubstreamAdmission {
public:
    explicit InboundSubstreamAdmission(StatsShard& stats) noexcept : connection_stats_(stats) {}
    [[nodiscard]] bool Hold(ConnectionLimiter::Admission admission, const session::Context& ctx, StatsShard& stats) {
        if (admission.reason != ConnectionLimiter::RejectReason::NONE) {
            RejectInboundAdmission(ctx, stats, admission.reason);
            return false;
        }
        reservation_ = std::move(admission.reservation);
        return true;
    }
private:
    ConnectionStatsScope connection_stats_;
    ConnectionLimiter::Reservation reservation_;
};

[[nodiscard]] inline std::optional<net::awaitable<ConnectionLimiter::Admission>>
AdmitInboundSubstream(const AdmissionEnvironment& environment, const session::Context& ctx) {
    return ReserveInboundConnection(environment, ConnectionLimiter::ReservationScope::Logical, ctx);
}

[[nodiscard]] inline UserProfile MakeUserProfile(const InboundUserSpec& spec) {
    UserProfile profile;
    profile.email = spec.email;
    profile.user_id = spec.user_id;
    profile.speed_limit = spec.speed_limit;
    profile.device_limit = spec.device_limit;
    return profile;
}

[[nodiscard]] inline RelayResult RejectInbound(StatsShard& stats, AsyncStream* stream, ErrorCode error) noexcept {
    if (stream) stream->CloseAbortive();
    if (error != ErrorCode::CANCELLED && error != ErrorCode::SOCKET_EOF) stats.OnError();
    RelayResult result;
    result.error = error;
    return result;
}

template <typename PreparedUser, typename AssignCredential>
[[nodiscard]] std::optional<::proxyman::inbound::UserSet>
BuildHashedInboundUsers(std::string_view protocol_name, const ::proxyman::inbound::BuildRequest& req,
                        std::span<const ::InboundUserSpec> specs, AssignCredential&& assign_credential) {
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
    return ::proxyman::inbound::UserSet{std::move(users)};
}
} // namespace proxy
