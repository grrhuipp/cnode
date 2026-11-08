#pragma once

#include "handshake_timeout.hpp"

#include "app/proxyman/inbound/factory.hpp"
#include "app/rate_limiter.hpp"
#include "app/relay_types.hpp"
#include "app/stats.hpp"
#include "common/asio_types.hpp"
#include "common/session.hpp"
#include "common/sharded_user_stats.hpp"
#include "common/target_address.hpp"
#include "common/user_profile.hpp"
#include "infra/log.hpp"
#include "transport/async_stream.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <string_view>
#include <vector>
#include <utility>

namespace proxy {

[[nodiscard]] inline net::awaitable<bool> CheckInboundIpBanned(
    ConnectionLimiter* limiter,
    session::Context& ctx) {
    ctx.inbound.user_id = 0;
    ctx.inbound.user_email.clear();
    if (limiter && ctx.inbound.HasProxyProtocolClientIP() &&
        co_await limiter->IsBanned(ctx.inbound.tag, ctx.inbound.source_ip)) {
        LOG_CONN_DEBUG(ctx, "Rejected banned IP {}", ctx.inbound.source_ip);
        LOG_ACCESS(FormatAccessLog(ctx, AccessStatus::Rejected, "IP banned"));
        co_return true;
    }
    co_return false;
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
    ctx.outbound.original_target = request.target;
    ctx.outbound.target = std::move(request.target);
    ctx.outbound.route_target = ctx.outbound.original_target;
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

namespace detail {

[[nodiscard]] inline net::awaitable<std::optional<UserOnlineSessionGuard>>
FinishAuthenticatedAdmission(
    UserOnlineTracker& tracker,
    session::Context& ctx,
    const UserProfile& profile,
    net::awaitable<std::optional<UserOnlineSessionGuard>> reservation) {
    auto user_session = co_await std::move(reservation);
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

}  // namespace detail

// The single session-level online-device admission for every inbound
// protocol, after BindAuthenticatedInbound. The returned guard owns the
// device reservation for the whole authenticated session; substreams inherit.
// `coordinator` owns the process-wide device quota.
[[nodiscard]] inline net::awaitable<std::optional<UserOnlineSessionGuard>>
AdmitAuthenticatedInbound(
    UserOnlineTracker& tracker,
    GroupCoordinator& coordinator,
    session::Context& ctx,
    const UserProfile& profile) {
    return detail::FinishAuthenticatedAdmission(
        tracker, ctx, profile,
        tracker.TryConnectSession(coordinator, ctx.inbound.tag, profile.user_id,
                                  ctx.inbound.source_ip, profile.device_limit));
}

// Sessions running inside an execution domain admit through its coordinator;
// registered users without one are a logic error.
[[nodiscard]] inline net::awaitable<std::optional<UserOnlineSessionGuard>>
AdmitAuthenticatedInbound(
    UserOnlineTracker& tracker,
    session::Context& ctx,
    const UserProfile& profile) {
    return detail::FinishAuthenticatedAdmission(
        tracker, ctx, profile,
        tracker.TryConnectSession(ctx.inbound.tag, profile.user_id,
                                  ctx.inbound.source_ip, profile.device_limit));
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
    if (limiter) {
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
    if (!tracker) {
        RejectNativeAssociation(ctx, stats, "missing user admission");
        co_return std::nullopt;
    }
    // The credential's stable session capability owns the tracker; quota
    // reservations remain tied to their original coordinator across handoff.
    std::optional<UserOnlineSessionGuard> user_session;
    if (limiter) {
        user_session = co_await proxy::AdmitAuthenticatedInbound(
            *tracker, limiter->Coordinator(), ctx, profile);
    } else {
        user_session = co_await proxy::AdmitAuthenticatedInbound(*tracker, ctx, profile);
    }
    if (!user_session) {
        stats.OnError();
        co_return std::nullopt;
    }
    admitted.user_session = std::move(*user_session);
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
    if (limiter) {
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

// The single credential-failure entry: one log shape and one ban counter for
// every protocol. Only a trusted client address may feed the ban table.
inline net::awaitable<void> RecordInboundAuthFailure(
    ConnectionLimiter* limiter,
    session::Context& ctx,
    std::string_view reason) {
    LogInboundAuthFailure(ctx, reason);
    if (limiter && ctx.inbound.HasProxyProtocolClientIP()) {
        try {
            co_await limiter->OnAuthFailTracked(ctx.inbound.tag, ctx.inbound.source_ip);
        } catch (const WorkerMailboxFull&) {
        } catch (const IoSystemError&) {
        }
    }
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

template <typename Tracker = ::UserOnlineTracker>
class InboundTrackerRuntime final : public ::proxyman::inbound::ProtocolRuntime {
public:
    [[nodiscard]] std::vector<::OnlineDevice>
    GetOnlineDevices(std::string_view tag) const override {
        return validator.GetOnlineDevices(tag);
    }

    Tracker validator;
};
using UserOnlineProtocolRuntime = InboundTrackerRuntime<::UserOnlineTracker>;

}  // namespace proxy
