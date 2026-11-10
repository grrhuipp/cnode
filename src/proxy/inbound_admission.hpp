#pragma once

#include "common/error.hpp"
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

#include <cstdint>
#include <new>
#include <memory>
#include <optional>
#include <span>
#include <string_view>
#include <vector>
#include <utility>

namespace proxy {

[[nodiscard]] inline bool ConsumeStreamReadTimeout(
    AsyncStream& stream) noexcept {
    return stream.ConsumePhaseDeadline() || stream.ConsumeIdleTimeout() ||
           stream.ConsumeReadTimeout();
}

[[nodiscard]] inline ErrorCode ResolveHandshakeReadFailure(
    AsyncStream& stream,
    ErrorCode fallback = ErrorCode::SOCKET_READ_FAILED) noexcept {
    return ConsumeStreamReadTimeout(stream) ? ErrorCode::TIMEOUT : fallback;
}

[[nodiscard]] inline bool ConsumeOutboundHandshakeTimeout(
    AsyncStream& stream,
    const PhaseDeadlineHandle& deadline) noexcept {
    return deadline.Expired() || ConsumeStreamReadTimeout(stream) ||
           stream.ConsumeWriteTimeout();
}

[[nodiscard]] inline ErrorCode ClassifyHandshakeReadException(
    AsyncStream& stream,
    const IoSystemError& error) noexcept {
    if (ConsumeStreamReadTimeout(stream) || error.code() == io_error::timed_out) {
        return ErrorCode::TIMEOUT;
    }
    if (error.code() == io_error::operation_aborted) {
        return ErrorCode::CANCELLED;
    }
    return ErrorCode::SOCKET_READ_FAILED;
}

[[nodiscard]] inline ErrorCode ClassifyOutboundHandshakeException(
    AsyncStream& stream,
    const PhaseDeadlineHandle& deadline,
    ErrorCode fallback = ErrorCode::SOCKET_WRITE_FAILED) noexcept {
    try {
        throw;
    } catch (const IoSystemError& error) {
        return (ConsumeOutboundHandshakeTimeout(stream, deadline) ||
                error.code() == io_error::timed_out)
            ? ErrorCode::TIMEOUT
            : MapAsioError(error.code());
    } catch (const transport::LinkError& error) {
        return (ConsumeOutboundHandshakeTimeout(stream, deadline) ||
                error.code() == ErrorCode::TIMEOUT)
            ? ErrorCode::TIMEOUT
            : error.code();
    } catch (const std::bad_alloc&) {
        return ErrorCode::RESOURCE_EXHAUSTED;
    } catch (...) {
        return ConsumeOutboundHandshakeTimeout(stream, deadline)
            ? ErrorCode::TIMEOUT
            : fallback;
    }
}

// Start of every protocol's authentication: clears any inherited identity and
// reports whether the client address needs the coordinator's ban lookup
// (only PROXY-protocol addresses under an enabled auth-ban policy).
[[nodiscard]] inline bool BeginInboundAuthentication(
    const ConnectionLimiter* limiter,
    session::Context& ctx) noexcept {
    ctx.inbound.user_id = 0;
    ctx.inbound.user_email.clear();
    return limiter && limiter->TracksAuthBan() && ctx.inbound.HasProxyProtocolClientIP();
}

// Coordinator lookup for an address BeginInboundAuthentication flagged.
[[nodiscard]] inline net::awaitable<bool> CheckInboundIpBanned(
    ConnectionLimiter& limiter,
    session::Context& ctx) {
    if (!co_await limiter.IsBanned(ctx.inbound.tag, ctx.inbound.source_ip)) {
        co_return false;
    }
    LOG_CONN_DEBUG(ctx, "Rejected banned IP {}", ctx.inbound.source_ip);
    LOG_ACCESS(FormatAccessLog(ctx, AccessStatus::Rejected, "IP banned"));
    co_return true;
}

// Request target resolved by a protocol together with its credential. Session
// protocols (AnyTLS, Hysteria) authenticate before any target exists.
struct InboundRequestTarget {
    Network network = Network::TCP;
    TargetAddress target;
    std::optional<ForwardedMetadata> forwarded = std::nullopt;
};

// The single writer of a request target into the session.
inline void BindInboundRequestTarget(
    session::Context& ctx,
    InboundRequestTarget request) {
    if (request.forwarded) {
        ctx.inbound.ApplyForwardedMetadata(*request.forwarded);
    }
    ctx.content.network = request.network;
    ctx.outbound.original_target = {};
    ctx.outbound.target = std::move(request.target);
    ctx.outbound.route_target = {};
}
// The single writer of an authenticated identity and its request target into
// the session. Protocols call it as soon as the credential matches, so their
// own later protocol rejections (flow, replay, transport) log the user and
// target; admission then runs on the published context.
inline void BindAuthenticatedInbound(
    session::Context& ctx,
    const UserProfile& profile,
    std::optional<InboundRequestTarget> request) {
    ctx.inbound.user_id = profile.user_id;
    ctx.inbound.user_email = profile.email;
    ctx.content.speed_limit = profile.speed_limit;
    if (request) BindInboundRequestTarget(ctx, std::move(*request));
}

// The single session-level online-device admission for every inbound
// protocol, after BindAuthenticatedInbound. The returned guard owns the
// device reservation for the whole authenticated session; substreams inherit.
[[nodiscard]] inline net::awaitable<std::optional<UserOnlineSessionGuard>>
AdmitAuthenticatedInbound(
    UserOnlineTracker& tracker,
    session::Context& ctx,
    const UserProfile& profile) {
    auto user_session = co_await tracker.TryConnectSession(
        ctx.inbound.tag, profile.user_id, ctx.inbound.source_ip,
        profile.device_limit);
    if (!user_session) {
        LOG_CONN_DEBUG(ctx, "User {} exceeded device limit ({}/{})",
                       profile.user_id,
                       tracker.OnlineDeviceCount(
                           ctx.inbound.tag, static_cast<uint64_t>(profile.user_id)),
                       profile.device_limit);
        LOG_ACCESS(FormatAccessLog(ctx, AccessStatus::Rejected, "device limit"));
        co_return std::nullopt;
    }
    if (ctx.outbound.target.IsValid()) {
        LOG_CONN_DEBUG(ctx, "authentication succeeded from {}:{} -> {}",
                       ctx.inbound.source_ip, ctx.inbound.source_port,
                       ctx.outbound.target);
    } else {
        LOG_CONN_DEBUG(ctx, "authentication succeeded from {}:{}",
                       ctx.inbound.source_ip, ctx.inbound.source_port);
    }
    co_return user_session;
}
// Ownership of every admission an association holds until it ends.
struct NativeAssociationAdmission {
    ConnectionLimiter::Reservation connection;
    ConnectionLimiter::Reservation ip;
    UserOnlineSessionGuard user_session;
};

inline void RejectNativeAssociation(const session::Context& ctx, StatsShard& stats,
                             std::string_view reason) {
    LOG_CONN_DEBUG(ctx, "UDP association rejected from {}:{} > {}",
                   ctx.inbound.source_ip, ctx.inbound.source_port, reason);
    LOG_ACCESS(FormatAccessLog(ctx, AccessStatus::Rejected, reason));
    stats.OnError();
}

// The unified admission contract for one native association, in TCP order:
// global and per-IP connection reservations, then session-level devices.
inline net::awaitable<std::optional<NativeAssociationAdmission>> AdmitNativeAssociation(
    session::Context& ctx,
    const UserProfile& profile,
    UserOnlineTracker* tracker,
    ConnectionLimiter* limiter,
    StatsShard& stats) {
    NativeAssociationAdmission admitted;
    if (limiter && limiter->TracksAdmission()) {
        const bool check_ban = ctx.inbound.HasProxyProtocolClientIP();
        auto physical = co_await limiter->ReservePhysical(
            ctx.inbound.tag, ctx.inbound.source_ip, check_ban);
        if (physical.reason != ConnectionLimiter::RejectReason::NONE) {
            RejectNativeAssociation(
                ctx, stats, ConnectionLimiter::RejectReasonToString(physical.reason));
            co_return std::nullopt;
        }
        admitted.connection = std::move(physical.reservation);
        auto ip = co_await limiter->ReserveIP(
            ctx.inbound.tag, ctx.inbound.source_ip, check_ban);
        if (ip.reason != ConnectionLimiter::RejectReason::NONE) {
            RejectNativeAssociation(
                ctx, stats, ConnectionLimiter::RejectReasonToString(ip.reason));
            co_return std::nullopt;
        }
        admitted.ip = std::move(ip.reservation);
    }
    if (tracker) {
        auto user_session =
            co_await proxy::AdmitAuthenticatedInbound(*tracker, ctx, profile);
        if (!user_session) {
            stats.OnError();
            co_return std::nullopt;
        }
        admitted.user_session = std::move(*user_session);
    }
    co_return std::move(admitted);
}

// Admission of one protocol-level substream (Mux.Cool child, AnyTLS SYN
// stream), held for the child's lifetime: the same logical connection-limit
// reservation against the physical family as HTTP/2-family logical streams,
// plus accepted/closed connection statistics. Device admission stays with the
// authenticated session; children inherit it through their context.
class InboundSubstreamAdmission {
public:
    InboundSubstreamAdmission(ConnectionStatsScope connection_stats,
                              ConnectionLimiter::Reservation reservation) noexcept
        : connection_stats_(std::move(connection_stats))
        , reservation_(std::move(reservation)) {}

private:
    ConnectionStatsScope connection_stats_;
    ConnectionLimiter::Reservation reservation_;
};

// Admission tracking off: callers build InboundSubstreamAdmission directly
// instead of entering the AdmitInboundSubstream coroutine.
[[nodiscard]] inline bool SubstreamAdmissionTracked(
    const ConnectionLimiter* limiter) noexcept {
    return limiter && limiter->TracksAdmission();
}

// The single substream admission entry. `ctx` is the child context inherited
// from the session (InitSubstreamFrom), carrying the physical family lease.
// A rejection is logged and counted here; the caller closes only that child.
[[nodiscard]] inline net::awaitable<std::optional<InboundSubstreamAdmission>>
AdmitInboundSubstream(
    ConnectionLimiter* limiter,
    StatsShard& stats,
    const session::Context& ctx) {
    ConnectionStatsScope connection_stats(stats);
    ConnectionLimiter::Reservation reservation;
    if (limiter && limiter->TracksAdmission()) {
        auto admission = co_await limiter->ReserveLogical(
            ctx.inbound.connection_family, ctx.inbound.tag, ctx.inbound.source_ip,
            ctx.inbound.HasProxyProtocolClientIP());
        if (admission.reason != ConnectionLimiter::RejectReason::NONE) {
            const char* reason = ConnectionLimiter::RejectReasonToString(admission.reason);
            LOG_CONN_DEBUG(ctx, "substream rejected from {}:{} > {}",
                           ctx.inbound.source_ip, ctx.inbound.source_port, reason);
            LOG_ACCESS(FormatAccessLog(ctx, AccessStatus::Rejected, reason));
            stats.OnError();
            co_return std::nullopt;
        }
        reservation = std::move(admission.reservation);
    }
    co_return InboundSubstreamAdmission(std::move(connection_stats), std::move(reservation));
}

// The single credential-failure log shape for every protocol.
inline void LogInboundAuthFailure(
    const session::Context& ctx,
    std::string_view reason) {
    LOG_CONN_WARN(ctx, "authentication failed from {}:{} > {}",
                  ctx.inbound.source_ip, ctx.inbound.source_port, reason);
    LOG_ACCESS(FormatAccessLog(ctx, AccessStatus::Rejected, reason));
}

// A credential key is already owned and salted before entering the coordinator.
// Only PROXY protocol addresses may additionally feed the independent IP rule.
inline net::awaitable<void> RecordInboundAuthFailure(
    ConnectionLimiter* limiter,
    session::Context& ctx,
    std::string_view reason,
    std::optional<AuthCredentialKey> credential = std::nullopt) {
    LogInboundAuthFailure(ctx, reason);
    const bool track_ip = limiter && limiter->TracksAuthBan() &&
                          ctx.inbound.HasProxyProtocolClientIP();
    if (limiter && (track_ip || credential)) {
        try {
            co_await limiter->OnAuthFailTracked(
                ctx.inbound.tag,
                track_ip ? std::string_view(ctx.inbound.source_ip) : std::string_view{},
                std::move(credential));
        } catch (const WorkerMailboxFull&) {
            LOG_CONN_WARN(ctx, "authentication failure tracking unavailable > mailbox full");
        } catch (const IoSystemError&) {
            LOG_CONN_WARN(ctx, "authentication failure tracking unavailable > coordinator I/O error");
        }
    }
}

struct PreparedInboundCredential {
    std::optional<AuthCredentialKey> key;
    ErrorCode error = ErrorCode::OK;
};

[[nodiscard]] inline net::awaitable<PreparedInboundCredential>
VerifyInboundCredential(
    ConnectionLimiter* limiter,
    session::Context& ctx,
    proxyman::inbound::UserProtocol protocol,
    std::span<const uint8_t> raw_credential) {
    if (!limiter) co_return PreparedInboundCredential{};
    const auto credential_revision =
        proxyman::inbound::UserStore::CredentialRevision(protocol, ctx.inbound.tag);
    const auto key = limiter->FingerprintCredential(
        ctx.inbound.tag, raw_credential, credential_revision);
    const auto reason = co_await limiter->CheckCredential(key);
    // A user publication that raced the lookup retires this fingerprint; the
    // protocol then matches against the current snapshot on its own.
    if (proxyman::inbound::UserStore::CredentialRevision(protocol, ctx.inbound.tag) !=
            credential_revision ||
        reason == ConnectionLimiter::RejectReason::NONE) {
        co_return PreparedInboundCredential{.key = key, .error = ErrorCode::OK};
    }
    co_await RecordInboundAuthFailure(
        limiter, ctx, ConnectionLimiter::RejectReasonToString(reason));
    co_return PreparedInboundCredential{
        .key = key,
        .error = reason == ConnectionLimiter::RejectReason::TRACKING_CAPACITY
            ? ErrorCode::RESOURCE_EXHAUSTED : ErrorCode::BLOCKED};
}

[[nodiscard]] inline UserProfile MakeUserProfile(const InboundUserSpec& spec) {
    UserProfile profile;
    profile.email = spec.email;
    profile.user_id = spec.user_id;
    profile.speed_limit = spec.speed_limit;
    profile.device_limit = spec.device_limit;
    return profile;
}

// The single pre-dispatch rejection exit. Peer EOF and local cancellation are
// normal endings and are not counted as errors.
[[nodiscard]] inline RelayResult RejectInbound(
    StatsShard& stats,
    AsyncStream* stream,
    ErrorCode error) noexcept {
    if (stream) {
        stream->CloseAbortive();
    }
    if (error != ErrorCode::CANCELLED && error != ErrorCode::SOCKET_EOF) {
        stats.OnError();
    }
    RelayResult result;
    result.error = error;
    return result;
}

class UserOnlineProtocolRuntime final : public ::proxyman::inbound::ProtocolRuntime {
public:
    [[nodiscard]] ::UserOnlineTracker* OnlineTracker() noexcept override {
        return &validator;
    }
    ::UserOnlineTracker validator;
};

[[nodiscard]] inline std::unique_ptr<::proxyman::inbound::ProtocolRuntime>
CreateUserOnlineProtocolRuntime(memory::worker_memory& pool) {
    return memory::MakeUnique<UserOnlineProtocolRuntime>(pool);
}

template <typename PreparedUser, typename AssignCredential>
[[nodiscard]] std::optional<::proxyman::inbound::UserSet>
BuildHashedInboundUsers(
    std::string_view protocol_name,
    const ::proxyman::inbound::BuildRequest& req,
    std::span<const ::InboundUserSpec> specs,
    AssignCredential&& assign_credential) {
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

}  // namespace proxy
