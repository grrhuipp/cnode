#include "acppnode/app/rate_limiter.hpp"
#include "acppnode/common/session.hpp"
#include <iostream>
#include <memory>
#include <string_view>
#include <string>
#include <vector>

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
    if (limiter->IsBanned(tag, ip)) return 1;

    inbound.client_ip_source = "http_header";
    record_auth_failure(inbound, ip);  // forwarded header must not count
    if (limiter->IsBanned(tag, ip)) return 2;

    inbound.client_ip_source = "proxy_protocol";
    inbound.source_ip.clear();
    if (inbound.HasProxyProtocolClientIP()) return 3;  // no usable PP source
    record_auth_failure(inbound, ip);
    if (limiter->IsBanned(tag, ip)) return 4;

    inbound.source_ip = ip;
    if (!inbound.HasProxyProtocolClientIP()) return 5;
    if (limiter->IsBanned(tag, ip)) return 6;
    record_auth_failure(inbound, ip);
    if (!limiter->IsBanned(tag, ip)) return 7;
    if (limiter->IsBanned(other_tag, ip)) return 8;
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
    // Exhaust tracking with distinct, live source addresses. Lack of tracking
    // storage must reject admission, not silently remove the per-IP policy.
    auto capacity = std::make_unique<acpp::ConnectionLimiter>(
        acpp::RateLimitConfig{.max_conn_per_ip = 1, .auth_fail_limit = 0});
    std::vector<std::string> admitted;
    std::string rejected;
    for (unsigned value = 0; value < 65536; ++value) {
        auto address = "198.18." + std::to_string(value >> 8) + "." +
                       std::to_string(value & 255);
        const auto reason = capacity->TryAcceptIP(tag, address);
        if (reason != acpp::ConnectionLimiter::RejectReason::NONE) {
            if (reason != acpp::ConnectionLimiter::RejectReason::TRACKING_CAPACITY) return 21;
            rejected = std::move(address);
            break;
        }
        admitted.push_back(std::move(address));
    }
    if (rejected.empty()) {
        std::cerr << "exhausted IP tracking admitted untracked connections\n";
        return 13;
    }
    for (const auto& address : admitted) capacity->ReleaseHash(acpp::Hash(address));
    if (capacity->TryAcceptIP(tag, rejected) !=
        acpp::ConnectionLimiter::RejectReason::NONE) return 14;
    if (capacity->TryAcceptIP(tag, rejected) !=
        acpp::ConnectionLimiter::RejectReason::MAX_CONNECTIONS_PER_IP) return 15;
    capacity->ReleaseHash(acpp::Hash(rejected));

    auto independent = std::make_unique<acpp::ConnectionLimiter>(
        acpp::RateLimitConfig{.max_connections = 1, .max_conn_per_ip = 1});
    if (independent->TryAcceptGlobal() !=
        acpp::ConnectionLimiter::RejectReason::NONE) return 16;
    if (independent->TryAcceptIP(tag, ip) !=
        acpp::ConnectionLimiter::RejectReason::NONE) return 17;
    independent->ReleaseHash(acpp::Hash(ip));
    if (independent->TryAcceptGlobal() !=
        acpp::ConnectionLimiter::RejectReason::MAX_CONNECTIONS) return 18;
    if (independent->TryAcceptIP(tag, ip) !=
        acpp::ConnectionLimiter::RejectReason::NONE) return 19;
    independent->ReleaseHash(acpp::Hash(ip));
    independent->ReleaseGlobal();
    if (independent->TryAcceptGlobal() !=
        acpp::ConnectionLimiter::RejectReason::NONE) return 20;
    independent->ReleaseGlobal();
    return 0;
}
