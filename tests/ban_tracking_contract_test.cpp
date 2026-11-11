#include <gtest/gtest.h>

#include "app/rate_limiter.hpp"
#include "app/connection_limiter_core.hpp"
#include <asio/co_spawn.hpp>
#include <exception>
#include <limits>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace {
using Core = app::ConnectionLimiterCore;
using Reason = app::ConnectionLimiter::RejectReason;
constexpr std::string_view kTag = "panel|vless|443";
constexpr std::string_view kOtherTag = "panel|vless|8443";
constexpr std::string_view kIP = "192.0.2.1";

// 封禁键与生产协调器一致：未启用 IP 封禁或来源为空时没有键，也就不会被封禁。
bool IsIPBanned(const Core& core, const std::optional<app::AuthCredentialKey>& ip_key, uint64_t now) {
    return ip_key && core.CheckIPBan(*ip_key, now) == Reason::IP_BANNED;
}

app::AuthCredentialKey Key(uint64_t value) {
    app::AuthCredentialKey key{};
    for (size_t i = 0; i < sizeof(value); ++i, value >>= 8)
        key[i] = static_cast<uint8_t>(value);
    return key;
}
} // namespace

TEST(BanTrackingContract, FixedWindowResetsAtBoundaryForBothRules) {
    app::RateLimitConfig config;
    config.ip_ban = {.enabled = true, .failure_limit = 10,
                     .window_seconds = 60, .ban_seconds = 180};
    Core limiter(config);
    const auto key = Key(1);
    const auto ip_key = limiter.ComputeIpBanKey(kTag, kIP);
    ASSERT_TRUE(ip_key);
    // Nine failures spread across the first window must not slide its start.
    for (unsigned i = 0; i < 5; ++i)
        limiter.OnAuthFailTracked(ip_key, key, 100);
    for (unsigned i = 0; i < 4; ++i)
        limiter.OnAuthFailTracked(ip_key, key, 159);
    EXPECT_FALSE(IsIPBanned(limiter, ip_key, 159));
    EXPECT_EQ(limiter.CheckCredential(key, 159), Reason::NONE);

    limiter.OnAuthFailTracked(ip_key, key, 160); // exact window boundary
    EXPECT_FALSE(IsIPBanned(limiter, ip_key, 160));
    EXPECT_EQ(limiter.CheckCredential(key, 160), Reason::NONE);
    for (unsigned i = 0; i < 8; ++i)
        limiter.OnAuthFailTracked(ip_key, key, 219);
    EXPECT_FALSE(IsIPBanned(limiter, ip_key, 219));
    EXPECT_EQ(limiter.CheckCredential(key, 219), Reason::NONE);
    limiter.OnAuthFailTracked(ip_key, key, 219);
    EXPECT_TRUE(IsIPBanned(limiter, ip_key, 219));
    EXPECT_EQ(limiter.CheckCredential(key, 219), Reason::CREDENTIAL_BANNED);
    EXPECT_EQ(limiter.TryAcceptIP(Core::IpHash(kIP), ip_key, 219), Reason::IP_BANNED);
    EXPECT_TRUE(IsIPBanned(limiter, ip_key, 398));
    EXPECT_EQ(limiter.CheckCredential(key, 398), Reason::CREDENTIAL_BANNED);
    EXPECT_FALSE(IsIPBanned(limiter, ip_key, 399));
    EXPECT_EQ(limiter.CheckCredential(key, 399), Reason::NONE);
}

TEST(BanTrackingContract, BannedFailuresNeverExtendExpiryOrAccumulate) {
    app::RateLimitConfig config;
    config.ip_ban = {.enabled = true, .failure_limit = 10,
                     .window_seconds = 60, .ban_seconds = 180};
    Core limiter(config);
    const auto key = Key(2);
    const auto ip_key = limiter.ComputeIpBanKey(kTag, kIP);
    ASSERT_TRUE(ip_key);
    for (unsigned i = 0; i < 10; ++i)
        limiter.OnAuthFailTracked(ip_key, key, 0); // epoch zero is a valid start
    for (unsigned i = 0; i < 20; ++i)
        limiter.OnAuthFailTracked(ip_key, key, 179);
    EXPECT_TRUE(IsIPBanned(limiter, ip_key, 179));
    EXPECT_EQ(limiter.CheckCredential(key, 179), Reason::CREDENTIAL_BANNED);
    EXPECT_FALSE(IsIPBanned(limiter, ip_key, 180));
    EXPECT_EQ(limiter.CheckCredential(key, 180), Reason::NONE);
    for (unsigned i = 0; i < 9; ++i)
        limiter.OnAuthFailTracked(ip_key, key, 180);
    EXPECT_FALSE(IsIPBanned(limiter, ip_key, 180));
    EXPECT_EQ(limiter.CheckCredential(key, 180), Reason::NONE);
    limiter.OnAuthFailTracked(ip_key, key, 180);
    EXPECT_TRUE(IsIPBanned(limiter, ip_key, 180));
    EXPECT_EQ(limiter.CheckCredential(key, 180), Reason::CREDENTIAL_BANNED);
}

TEST(BanTrackingContract, MonotonicSecondsDoNotWrapAtUint32Boundary) {
    app::RateLimitConfig config;
    config.ip_ban = {.enabled = true, .failure_limit = 10,
                     .window_seconds = 60, .ban_seconds = 180};
    Core limiter(config);
    const auto key = Key(3);
    const auto ip_key = limiter.ComputeIpBanKey(kTag, kIP);
    ASSERT_TRUE(ip_key);
    constexpr uint64_t now = static_cast<uint64_t>(std::numeric_limits<uint32_t>::max()) - 2;
    for (unsigned i = 0; i < 10; ++i)
        limiter.OnAuthFailTracked(ip_key, key, now);
    EXPECT_TRUE(IsIPBanned(limiter, ip_key, now + 179));
    EXPECT_EQ(limiter.CheckCredential(key, now + 179), Reason::CREDENTIAL_BANNED);
    EXPECT_FALSE(IsIPBanned(limiter, ip_key, now + 180));
    EXPECT_EQ(limiter.CheckCredential(key, now + 180), Reason::NONE);
}

TEST(BanTrackingContract, TagsCredentialsAndIPRulesAreIndependent) {
    app::RateLimitConfig config;
    config.ip_ban = {.enabled = true, .failure_limit = 2,
                     .window_seconds = 60, .ban_seconds = 180};
    Core limiter(config);
    const auto key = Key(4);
    const auto other = Key(5);
    const auto ip_key = limiter.ComputeIpBanKey(kTag, kIP);
    const auto other_tag_ip_key = limiter.ComputeIpBanKey(kOtherTag, kIP);
    ASSERT_TRUE(ip_key && other_tag_ip_key);
    // One failed credential across ten source IPs reaches the credential limit;
    // no individual source reaches the independently configured IP threshold.
    for (unsigned i = 0; i < 10; ++i) {
        limiter.OnAuthFailTracked(
            limiter.ComputeIpBanKey(kTag, "192.0.2." + std::to_string(i + 1)), key, 100);
    }
    EXPECT_EQ(limiter.CheckCredential(key, 100), Reason::CREDENTIAL_BANNED);
    EXPECT_EQ(limiter.CheckCredential(other, 100), Reason::NONE);
    EXPECT_FALSE(IsIPBanned(limiter, ip_key, 100));
    limiter.OnAuthFailTracked(ip_key, std::nullopt, 100);
    EXPECT_TRUE(IsIPBanned(limiter, ip_key, 100));
    EXPECT_FALSE(IsIPBanned(limiter, other_tag_ip_key, 100));
    EXPECT_EQ(limiter.CheckCredential(other, 100), Reason::NONE);
    // An empty source must not consume an IP-ban slot or create an empty-IP ban.
    const auto empty_source_key = limiter.ComputeIpBanKey(kTag, {});
    EXPECT_FALSE(empty_source_key);
    for (unsigned i = 0; i < 10; ++i)
        limiter.OnAuthFailTracked(empty_source_key, other, 100);
    EXPECT_FALSE(IsIPBanned(limiter, empty_source_key, 100));
    EXPECT_EQ(limiter.CheckCredential(other, 100), Reason::CREDENTIAL_BANNED);
}

TEST(BanTrackingContract, ExactCredentialKeysHaveIndependentFailureCounters) {
    app::RateLimitConfig config;
    config.ip_ban.enabled = false;
    Core limiter(config);
    app::AuthCredentialKey first{};
    app::AuthCredentialKey second{};
    second.back() = 1; // Identical prefixes are not sufficient to identify a key.
    for (unsigned i = 0; i < 9; ++i)
        limiter.OnAuthFailTracked(std::nullopt, first, 100);
    limiter.OnAuthFailTracked(std::nullopt, second, 100);
    EXPECT_EQ(limiter.CheckCredential(first, 100), Reason::NONE);
    EXPECT_EQ(limiter.CheckCredential(second, 100), Reason::NONE);
    limiter.OnAuthFailTracked(std::nullopt, first, 100);
    EXPECT_EQ(limiter.CheckCredential(first, 100), Reason::CREDENTIAL_BANNED);
    EXPECT_EQ(limiter.CheckCredential(second, 100), Reason::NONE);
}

TEST(BanTrackingContract, CredentialFingerprintUsesTagBinaryInputAndPrivateSalt) {
    net::io_context io, other_io;
    auto coordinator = std::make_shared<app::GroupCoordinator>(io);
    auto other_coordinator = std::make_shared<app::GroupCoordinator>(other_io);
    const app::RateLimitConfig config;
    auto limiter = app::ConnectionLimiter::Acquire(config, coordinator);
    auto other_limiter = app::ConnectionLimiter::Acquire(config, other_coordinator);
    const std::array<uint8_t, 3> credential{'a', 0, 'b'};
    const auto key = limiter->FingerprintCredential(kTag, credential, 1);

    Core core(config);
    for (unsigned i = 0; i < 10; ++i)
        core.OnAuthFailTracked(std::nullopt, key, 100);
    EXPECT_EQ(core.CheckCredential(key, 100), Reason::CREDENTIAL_BANNED);
    EXPECT_EQ(core.CheckCredential(
        limiter->FingerprintCredential(kTag, std::span(credential).first(1), 1), 100),
        Reason::NONE);
    EXPECT_EQ(core.CheckCredential(
        other_limiter->FingerprintCredential(kTag, credential, 1), 100), Reason::NONE);
    const std::array<uint8_t, 2> bc{'b', 'c'};
    const std::array<uint8_t, 1> c{'c'};
    const auto first_split = limiter->FingerprintCredential("a", bc, 1);
    for (unsigned i = 0; i < 10; ++i)
        core.OnAuthFailTracked(std::nullopt, first_split, 100);
    EXPECT_EQ(core.CheckCredential(
        limiter->FingerprintCredential("ab", c, 1), 100), Reason::NONE);
    EXPECT_EQ(core.CheckCredential(limiter->FingerprintCredential(kOtherTag, credential, 1), 100),
              Reason::NONE);
    // Publishing a changed credential set invalidates the old negative cache,
    // while the old snapshot's key remains banned until its own expiry.
    const auto updated_key = limiter->FingerprintCredential(kTag, credential, 2);
    EXPECT_EQ(core.CheckCredential(updated_key, 100), Reason::NONE);
    core.OnAuthFailTracked(std::nullopt, updated_key, 100);
    EXPECT_EQ(core.CheckCredential(updated_key, 100), Reason::NONE);
    EXPECT_EQ(core.CheckCredential(key, 100), Reason::CREDENTIAL_BANNED);
}

TEST(BanTrackingContract, DisabledIPBanDoesNotAffectConnectionQuotas) {
    app::RateLimitConfig config;
    config.max_connections = 1;
    config.max_conn_per_ip = 1;
    config.ip_ban = {.enabled = false, .failure_limit = 1,
                     .window_seconds = 60, .ban_seconds = 180};
    Core limiter(config);
    EXPECT_FALSE(limiter.TracksAuthBan());
    const auto ip_key = limiter.ComputeIpBanKey(kTag, kIP);
    EXPECT_FALSE(ip_key);
    const auto ip_hash = Core::IpHash(kIP);
    for (unsigned i = 0; i < 10; ++i)
        limiter.OnAuthFailTracked(ip_key, Key(6), 100);
    EXPECT_FALSE(IsIPBanned(limiter, ip_key, 100));
    EXPECT_EQ(limiter.CheckCredential(Key(6), 100), Reason::CREDENTIAL_BANNED);
    EXPECT_EQ(limiter.TryAcceptGlobal(), Reason::NONE);
    EXPECT_EQ(limiter.TryAcceptIP(ip_hash, ip_key, 100), Reason::NONE);
    EXPECT_EQ(limiter.TryAcceptIP(ip_hash, ip_key, 100), Reason::MAX_CONNECTIONS_PER_IP);
    EXPECT_EQ(limiter.TryAcceptGlobal(), Reason::MAX_CONNECTIONS);
    limiter.ReleaseHash(ip_hash);
    EXPECT_EQ(limiter.TryAcceptGlobal(), Reason::MAX_CONNECTIONS);
    EXPECT_EQ(limiter.TryAcceptIP(ip_hash, ip_key, 100), Reason::NONE);
    limiter.ReleaseHash(ip_hash);
    limiter.ReleaseGlobal();
    EXPECT_EQ(limiter.TryAcceptGlobal(), Reason::NONE);
    limiter.ReleaseGlobal();
}

TEST(BanTrackingContract, ExplicitIPBanBypassStillEnforcesConnectionQuota) {
    app::RateLimitConfig config;
    config.max_conn_per_ip = 1;
    config.ip_ban = {.enabled = true, .failure_limit = 1,
                     .window_seconds = 60, .ban_seconds = 180};
    Core limiter(config);
    const auto ip_key = limiter.ComputeIpBanKey(kTag, kIP);
    ASSERT_TRUE(ip_key);
    const auto ip_hash = Core::IpHash(kIP);
    limiter.OnAuthFailTracked(ip_key, std::nullopt, 100);
    EXPECT_EQ(limiter.TryAcceptIP(ip_hash, ip_key, 100), Reason::IP_BANNED);
    EXPECT_EQ(limiter.TryAcceptIP(ip_hash, std::nullopt, 100), Reason::NONE);
    EXPECT_EQ(limiter.TryAcceptIP(ip_hash, std::nullopt, 100), Reason::MAX_CONNECTIONS_PER_IP);
    limiter.ReleaseHash(ip_hash);
}

TEST(BanTrackingContract, DisabledIPOnlyOperationsSkipClosedMailbox) {
    net::io_context io;
    auto coordinator = std::make_shared<app::GroupCoordinator>(io);
    app::RateLimitConfig config;
    config.ip_ban.enabled = false;
    auto limiter = app::ConnectionLimiter::Acquire(config, coordinator);
    coordinator->CloseAdmission();
    bool completed = false;
    std::exception_ptr failure;
    auto exercise = [&]() -> net::awaitable<void> {
        EXPECT_FALSE(co_await limiter->IsBanned(kTag, kIP));
        co_await limiter->OnAuthFailTracked(kTag, kIP);
        completed = true;
    };
    net::co_spawn(io, exercise(), [&](std::exception_ptr error) { failure = error; });
    io.run();
    EXPECT_FALSE(failure);
    EXPECT_TRUE(completed);
}

TEST(BanTrackingContract, ConnectionCapacityRejectsAndReclaimsReleasedSlots) {
    app::RateLimitConfig config;
    config.max_conn_per_ip = 1;
    config.ip_ban.enabled = false;
    Core limiter(config);
    std::vector<std::string> admitted;
    std::string rejected;
    for (unsigned value = 0; value <= Core::kSlotCount; ++value) {
        auto address = "198.18." + std::to_string(value >> 8) + "." +
                       std::to_string(value & 255);
        const auto reason = limiter.TryAcceptIP(Core::IpHash(address), std::nullopt, 100);
        if (reason != Reason::NONE) {
            ASSERT_EQ(reason, Reason::TRACKING_CAPACITY);
            rejected = std::move(address);
            break;
        }
        admitted.push_back(std::move(address));
    }
    ASSERT_FALSE(rejected.empty());
    for (const auto& address : admitted) limiter.ReleaseHash(Core::IpHash(address));
    const auto rejected_hash = Core::IpHash(rejected);
    EXPECT_EQ(limiter.TryAcceptIP(rejected_hash, std::nullopt, 100), Reason::NONE);
    EXPECT_EQ(limiter.TryAcceptIP(rejected_hash, std::nullopt, 100),
              Reason::MAX_CONNECTIONS_PER_IP);
    limiter.ReleaseHash(rejected_hash);
}

TEST(BanTrackingContract, CredentialQueriesDoNotInsertAndSaturationFailsClosedUntilExpiry) {
    app::RateLimitConfig config;
    config.ip_ban.enabled = false;
    config.max_conn_per_ip = 1;
    Core limiter(config);
    // More unknown queries than physical slots must never allocate tracking state.
    for (uint64_t value = 0; value < Core::kSlotCount * 2; ++value)
        ASSERT_EQ(limiter.CheckCredential(Key(value), 100), Reason::NONE);

    uint64_t rejected = Core::kSlotCount + 1;
    for (uint64_t value = 0; value <= Core::kSlotCount; ++value) {
        const auto reason = limiter.CheckCredential(Key(value), 100);
        if (reason == Reason::TRACKING_CAPACITY) {
            rejected = value;
            break;
        }
        ASSERT_EQ(reason, Reason::NONE); // distinct keys must not share counters/bans
        limiter.OnAuthFailTracked(std::nullopt, Key(value), 100);
        ASSERT_EQ(limiter.CheckCredential(Key(value), 100), Reason::NONE);
    }
    ASSERT_LE(rejected, Core::kSlotCount);
    EXPECT_EQ(limiter.CheckCredential(Key(rejected), 159), Reason::TRACKING_CAPACITY);
    EXPECT_EQ(limiter.TryAcceptIP(Core::IpHash(kIP), std::nullopt, 159), Reason::NONE);
    limiter.ReleaseHash(Core::IpHash(kIP)); // failure-table saturation consumes no quota
    EXPECT_EQ(limiter.CheckCredential(Key(rejected), 160), Reason::NONE);
    for (unsigned i = 0; i < 10; ++i)
        limiter.OnAuthFailTracked(std::nullopt, Key(rejected), 160);
    EXPECT_EQ(limiter.CheckCredential(Key(rejected), 160), Reason::CREDENTIAL_BANNED);
    EXPECT_EQ(limiter.CheckCredential(Key(rejected), 339), Reason::CREDENTIAL_BANNED);
    EXPECT_EQ(limiter.CheckCredential(Key(rejected), 340), Reason::NONE);
}

TEST(BanTrackingContract, IPFailureCapacityIsIndependentAndExpiredSlotsAreReusable) {
    app::RateLimitConfig config;
    config.max_conn_per_ip = 1;
    config.ip_ban = {.enabled = true, .failure_limit = 1,
                     .window_seconds = 60, .ban_seconds = 180};
    Core limiter(config);
    std::string rejected;
    for (unsigned value = 0; value <= Core::kSlotCount; ++value) {
        auto address = "198.19." + std::to_string(value >> 8) + "." +
                       std::to_string(value & 255);
        const auto address_key = limiter.ComputeIpBanKey(kTag, address);
        ASSERT_TRUE(address_key);
        const auto reason = limiter.CheckIPBan(*address_key, 100);
        if (reason == Reason::TRACKING_CAPACITY) {
            rejected = std::move(address);
            break;
        }
        ASSERT_EQ(reason, Reason::NONE);
        limiter.OnAuthFailTracked(address_key, std::nullopt, 100);
        ASSERT_TRUE(IsIPBanned(limiter, address_key, 100));
    }
    ASSERT_FALSE(rejected.empty());
    const auto rejected_key = limiter.ComputeIpBanKey(kTag, rejected);
    const auto rejected_hash = Core::IpHash(rejected);
    EXPECT_EQ(limiter.TryAcceptIP(rejected_hash, rejected_key, 279), Reason::TRACKING_CAPACITY);
    EXPECT_EQ(limiter.CheckCredential(Key(7), 279), Reason::NONE);
    for (unsigned i = 0; i < 10; ++i)
        limiter.OnAuthFailTracked(std::nullopt, Key(7), 279);
    EXPECT_EQ(limiter.CheckCredential(Key(7), 279), Reason::CREDENTIAL_BANNED);
    EXPECT_EQ(limiter.TryAcceptIP(rejected_hash, std::nullopt, 279), Reason::NONE);
    limiter.ReleaseHash(rejected_hash);
    EXPECT_EQ(limiter.CheckIPBan(*rejected_key, 280), Reason::NONE);
    limiter.OnAuthFailTracked(rejected_key, std::nullopt, 280);
    EXPECT_EQ(limiter.TryAcceptIP(rejected_hash, rejected_key, 280), Reason::IP_BANNED);
}

TEST(BanTrackingContract, ReconstructedLimiterStartsWithoutQuotasOrBans) {
    app::RateLimitConfig config;
    config.max_connections = 1;
    config.max_conn_per_ip = 1;
    config.ip_ban = {.enabled = true, .failure_limit = 1,
                     .window_seconds = 60, .ban_seconds = 180};
    const auto credential = Key(42);
    const auto ip_hash = Core::IpHash(kIP);
    for (unsigned cycle = 0; cycle < 3; ++cycle) {
        Core limiter(config);
        const auto ip_key = limiter.ComputeIpBanKey(kTag, kIP);
        ASSERT_TRUE(ip_key);
        EXPECT_EQ(limiter.CheckIPBan(*ip_key, 100), Reason::NONE);
        EXPECT_EQ(limiter.CheckCredential(credential, 100), Reason::NONE);
        EXPECT_EQ(limiter.TryAcceptGlobal(), Reason::NONE);
        EXPECT_EQ(limiter.TryAcceptGlobal(), Reason::MAX_CONNECTIONS);
        EXPECT_EQ(limiter.TryAcceptIP(ip_hash, ip_key, 100), Reason::NONE);
        EXPECT_EQ(limiter.TryAcceptIP(ip_hash, ip_key, 100), Reason::MAX_CONNECTIONS_PER_IP);
        for (unsigned failure = 0; failure < 10; ++failure)
            limiter.OnAuthFailTracked(ip_key, credential, 100);
        EXPECT_EQ(limiter.CheckIPBan(*ip_key, 100), Reason::IP_BANNED);
        EXPECT_EQ(limiter.CheckCredential(credential, 100), Reason::CREDENTIAL_BANNED);
    }
}
