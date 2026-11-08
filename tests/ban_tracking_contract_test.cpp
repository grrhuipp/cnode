#include <gtest/gtest.h>

#include "app/rate_limiter.hpp"
#include "common/session.hpp"
#include <iostream>
#include <memory>
#include <string_view>
#include <string>
#include <vector>

TEST(BanTrackingContract, Contract) {
    ::RateLimitConfig config;
    config.auth_fail_limit = 1;
    config.auth_fail_window = 60;
    config.auth_ban_seconds = 60;

    auto limiter = std::make_unique<::ConnectionLimiterCore>(config);
    constexpr std::string_view tag = "panel|vmess|443";
    constexpr std::string_view other_tag = "panel|vmess|8443";
    constexpr std::string_view ip = "192.0.2.1";

    auto record_auth_failure = [&](const ::session::Inbound& inbound,
                                   std::string_view source_ip) {
        if (inbound.HasProxyProtocolClientIP()) {
            limiter->OnAuthFailTracked(tag, source_ip);
        }
    };

    ::session::Inbound inbound;
    inbound.source_ip = ip;
    record_auth_failure(inbound, ip);  // socket peer must not count
    ASSERT_FALSE((limiter->IsBanned(tag, ip)));

    inbound.client_ip_source = "http_header";
    record_auth_failure(inbound, ip);  // forwarded header must not count
    ASSERT_FALSE((limiter->IsBanned(tag, ip)));

    inbound.client_ip_source = "proxy_protocol";
    inbound.source_ip.clear();
    ASSERT_FALSE((inbound.HasProxyProtocolClientIP()));  // no usable PP source
    record_auth_failure(inbound, ip);
    ASSERT_FALSE((limiter->IsBanned(tag, ip)));

    inbound.source_ip = ip;
    ASSERT_FALSE((!inbound.HasProxyProtocolClientIP()));
    ASSERT_FALSE((limiter->IsBanned(tag, ip)));
    record_auth_failure(inbound, ip);
    ASSERT_FALSE((!limiter->IsBanned(tag, ip)));
    ASSERT_FALSE((limiter->IsBanned(other_tag, ip)));
    ASSERT_FALSE((limiter->TryAcceptIP(tag, ip)
        != ::ConnectionLimiterCore::RejectReason::IP_BANNED));
    ASSERT_FALSE((limiter->TryAcceptIP(tag, "192.0.2.2")
        != ::ConnectionLimiterCore::RejectReason::NONE));

    ::RateLimitConfig limits_config;
    limits_config.auth_fail_limit = 1;
    limits_config.max_conn_per_ip = 1;
    auto limits = std::make_unique<::ConnectionLimiterCore>(limits_config);
    limits->OnAuthFailTracked(tag, ip);
    ASSERT_FALSE((limits->TryAcceptIP(tag, ip, false)
        != ::ConnectionLimiterCore::RejectReason::NONE));
    ASSERT_FALSE((limits->TryAcceptIP(tag, ip, false)
        != ::ConnectionLimiterCore::RejectReason::MAX_CONNECTIONS_PER_IP));
    // Exhaust tracking with distinct, live source addresses. Lack of tracking
    // storage must reject admission, not silently remove the per-IP policy.
    auto capacity = std::make_unique<::ConnectionLimiterCore>(
        ::RateLimitConfig{.max_conn_per_ip = 1, .auth_fail_limit = 0});
    std::vector<std::string> admitted;
    std::string rejected;
    for (unsigned value = 0; value < 65536; ++value) {
        auto address = "198.18." + std::to_string(value >> 8) + "." +
                       std::to_string(value & 255);
        const auto reason = capacity->TryAcceptIP(tag, address);
        if (reason != ::ConnectionLimiterCore::RejectReason::NONE) {
            ASSERT_FALSE((reason != ::ConnectionLimiterCore::RejectReason::TRACKING_CAPACITY));
            rejected = std::move(address);
            break;
        }
        admitted.push_back(std::move(address));
    }
    if (rejected.empty()) {
        std::cerr << "exhausted IP tracking admitted untracked connections\n";
        FAIL() << "exhausted IP tracking admitted untracked connections";
    }
    for (const auto& address : admitted) capacity->ReleaseHash(::ConnectionLimiterCore::IpHash(address));
    ASSERT_FALSE((capacity->TryAcceptIP(tag, rejected) !=
        ::ConnectionLimiterCore::RejectReason::NONE));
    ASSERT_FALSE((capacity->TryAcceptIP(tag, rejected) !=
        ::ConnectionLimiterCore::RejectReason::MAX_CONNECTIONS_PER_IP));
    capacity->ReleaseHash(::ConnectionLimiterCore::IpHash(rejected));

    auto independent = std::make_unique<::ConnectionLimiterCore>(
        ::RateLimitConfig{.max_connections = 1, .max_conn_per_ip = 1});
    ASSERT_FALSE((independent->TryAcceptGlobal() !=
        ::ConnectionLimiterCore::RejectReason::NONE));
    ASSERT_FALSE((independent->TryAcceptIP(tag, ip) !=
        ::ConnectionLimiterCore::RejectReason::NONE));
    independent->ReleaseHash(::ConnectionLimiterCore::IpHash(ip));
    ASSERT_FALSE((independent->TryAcceptGlobal() !=
        ::ConnectionLimiterCore::RejectReason::MAX_CONNECTIONS));
    ASSERT_FALSE((independent->TryAcceptIP(tag, ip) !=
        ::ConnectionLimiterCore::RejectReason::NONE));
    independent->ReleaseHash(::ConnectionLimiterCore::IpHash(ip));
    independent->ReleaseGlobal();
    ASSERT_FALSE((independent->TryAcceptGlobal() !=
        ::ConnectionLimiterCore::RejectReason::NONE));
    independent->ReleaseGlobal();
    // Multiple auth failures within the same second must accumulate and reach ban limit.
    auto multi_fail = std::make_unique<::ConnectionLimiterCore>(
        ::RateLimitConfig{.auth_fail_limit = 3, .auth_fail_window = 60, .auth_ban_seconds = 60});
    multi_fail->OnAuthFailTracked(tag, "192.0.2.55");
    ASSERT_FALSE((multi_fail->IsBanned(tag, "192.0.2.55")));
    multi_fail->OnAuthFailTracked(tag, "192.0.2.55");
    ASSERT_FALSE((multi_fail->IsBanned(tag, "192.0.2.55")));
    multi_fail->OnAuthFailTracked(tag, "192.0.2.55");
    ASSERT_FALSE((!multi_fail->IsBanned(tag, "192.0.2.55")));
}
