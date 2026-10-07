#include "acppnode/app/rate_limiter.hpp"
#include "acppnode/common/session.hpp"
#include "acppnode/proxy/inbound.hpp"

#include <concepts>
#include <memory>
#include <string_view>

namespace {

template <typename T>
concept MutableBanTracking = requires(T& handler) {
    handler.SetBanTrackingEnabled(true);
};

static_assert(!MutableBanTracking<acpp::Inbound>);

}  // namespace

int main() {
    acpp::RateLimitConfig config;
    config.auth_fail_limit = 1;
    config.auth_fail_window = 60;
    config.auth_ban_seconds = 60;

    auto limiter = std::make_unique<acpp::ConnectionLimiter>(config);
    constexpr std::string_view tag = "panel|vmess|443";
    constexpr std::string_view other_tag = "panel|vmess|8443";
    constexpr std::string_view ip = "192.0.2.1";

    auto record_auth_failure = [&](const acpp::session::Inbound& inbound,
                                   std::string_view source_ip) {
        if (inbound.HasProxyProtocolClientIP()) {
            limiter->OnAuthFailTracked(tag, source_ip);
        }
    };

    acpp::session::Inbound inbound;
    inbound.source_ip = ip;
    record_auth_failure(inbound, ip);  // socket peer must not count
    if (limiter->GetLimiter().IsBanned(tag, ip)) return 1;

    inbound.client_ip_source = "http_header";
    record_auth_failure(inbound, ip);  // forwarded header must not count
    if (limiter->GetLimiter().IsBanned(tag, ip)) return 2;

    inbound.client_ip_source = "proxy_protocol";
    inbound.source_ip.clear();
    if (inbound.HasProxyProtocolClientIP()) return 3;  // no usable PP source
    record_auth_failure(inbound, ip);
    if (limiter->GetLimiter().IsBanned(tag, ip)) return 4;

    inbound.source_ip = ip;
    if (!inbound.HasProxyProtocolClientIP()) return 5;
    if (limiter->GetLimiter().IsBanned(tag, ip)) return 6;
    record_auth_failure(inbound, ip);
    if (!limiter->GetLimiter().IsBanned(tag, ip)) return 7;
    if (limiter->GetLimiter().IsBanned(other_tag, ip)) return 8;
    if (limiter->TryAcceptIP(tag, ip)
        != acpp::ConnectionLimiter::RejectReason::IP_BANNED) {
        return 9;
    }
    if (limiter->TryAcceptIP(tag, "192.0.2.2")
        != acpp::ConnectionLimiter::RejectReason::NONE) {
        return 10;
    }

    acpp::RateLimitConfig limits_config;
    limits_config.auth_fail_limit = 1;
    limits_config.max_conn_per_ip = 1;
    auto limits = std::make_unique<acpp::ConnectionLimiter>(limits_config);
    limits->OnAuthFailTracked(tag, ip);
    if (limits->TryAcceptIP(tag, ip, false)
        != acpp::ConnectionLimiter::RejectReason::NONE) {
        return 11;  // non-PP skips the auth ban but still enters IP limits
    }
    if (limits->TryAcceptIP(tag, ip, false)
        != acpp::ConnectionLimiter::RejectReason::MAX_CONNECTIONS_PER_IP) {
        return 12;
    }
    return 0;
}
