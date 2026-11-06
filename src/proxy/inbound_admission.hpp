#pragma once

#include "handshake_timeout.hpp"

#include "acppnode/app/proxyman/inbound/factory.hpp"
#include "acppnode/app/rate_limiter.hpp"
#include "acppnode/app/relay_types.hpp"
#include "acppnode/app/stats.hpp"
#include "acppnode/common/asio_types.hpp"
#include "acppnode/common/session.hpp"
#include "acppnode/common/sharded_user_stats.hpp"
#include "acppnode/common/target_address.hpp"
#include "acppnode/common/user_profile.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/transport/async_stream.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <string_view>
#include <vector>

namespace acpp::proxy {

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
};

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
    if (request) {
        ctx.content.network = request->network;
        ctx.outbound.original_target = request->target;
        ctx.outbound.target = std::move(request->target);
    }
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
        ctx.inbound.tag, profile.user_id, ctx.inbound.source_ip, profile.device_limit);
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

// The single credential-failure entry: one log shape and one ban counter for
// every protocol. Only a trusted client address may feed the ban table.
inline net::awaitable<void> RecordInboundAuthFailure(
    ConnectionLimiter* limiter,
    session::Context& ctx,
    std::string_view reason) {
    LOG_CONN_WARN(ctx, "authentication failed from {}:{} > {}",
                  ctx.inbound.source_ip, ctx.inbound.source_port, reason);
    LOG_ACCESS(FormatAccessLog(ctx, AccessStatus::Rejected, reason));
    if (limiter && ctx.inbound.HasProxyProtocolClientIP()) {
        co_await limiter->OnAuthFailTracked(ctx.inbound.tag, ctx.inbound.source_ip);
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

template <typename Tracker = ::acpp::UserOnlineTracker>
class InboundTrackerRuntime final : public ::acpp::proxyman::inbound::ProtocolRuntime {
public:
    [[nodiscard]] std::vector<::acpp::OnlineDevice>
    GetOnlineDevices(std::string_view tag) const override {
        return validator.GetOnlineDevices(tag);
    }

    Tracker validator;
};
using UserOnlineProtocolRuntime = InboundTrackerRuntime<::acpp::UserOnlineTracker>;

}  // namespace acpp::proxy
