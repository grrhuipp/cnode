#include "acppnode/app/rate_limiter.hpp"
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

    if (limiter->GetLimiter().IsBanned(tag, ip)) return 1;
    limiter->OnAuthFailTracked(tag, ip);
    if (!limiter->GetLimiter().IsBanned(tag, ip)) return 2;
    if (limiter->GetLimiter().IsBanned(other_tag, ip)) return 3;
    if (limiter->TryAcceptIP(tag, ip)
        != acpp::ConnectionLimiter::RejectReason::IP_BANNED) {
        return 4;
    }
    return 0;
}
