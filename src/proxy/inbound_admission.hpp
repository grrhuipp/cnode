#pragma once

#include "handshake_timeout.hpp"

#include "acppnode/app/proxyman/inbound/factory.hpp"
#include "acppnode/app/rate_limiter.hpp"
#include "acppnode/common/asio_types.hpp"
#include "acppnode/common/session.hpp"
#include "acppnode/common/sharded_user_stats.hpp"
#include "acppnode/infra/log.hpp"

#include <cstdint>
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

[[nodiscard]] inline net::awaitable<std::optional<UserOnlineSessionGuard>>
TryAcquireInboundUserSession(
    UserOnlineTracker& validator,
    std::string_view tag,
    int64_t user_id,
    uint32_t device_limit,
    session::Context& ctx) {
    auto user_session = co_await validator.TryConnectSession(
        tag, user_id, ctx.inbound.source_ip, device_limit);
    if (!user_session) {
        LOG_CONN_DEBUG(ctx, "User {} exceeded device limit ({}/{})",
                       user_id,
                       validator.OnlineDeviceCount(tag, static_cast<uint64_t>(user_id)),
                       device_limit);
        LOG_ACCESS(FormatAccessLog(ctx, AccessStatus::Rejected, "device limit"));
    }
    co_return user_session;
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
