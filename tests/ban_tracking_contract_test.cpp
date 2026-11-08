#include <gtest/gtest.h>

#include "app/rate_limiter.hpp"
#include <asio/co_spawn.hpp>
#include <exception>
#include <limits>
#include <memory>
#include <string>
#include <vector>

namespace {
using Core = ConnectionLimiterCore;
using Reason = Core::RejectReason;
constexpr std::string_view kTag = "panel|vless|443";
constexpr std::string_view kOtherTag = "panel|vless|8443";
constexpr std::string_view kIP = "192.0.2.1";

AuthCredentialKey Key(uint64_t value) {
    AuthCredentialKey key{};
    for (size_t i = 0; i < sizeof(value); ++i, value >>= 8)
        key[i] = static_cast<uint8_t>(value);
    return key;
}
} // namespace

TEST(BanTrackingContract, FixedWindowResetsAtBoundaryForBothRules) {
    RateLimitConfig config;
    config.ip_ban = {.enabled = true, .failure_limit = 10,
                     .window_seconds = 60, .ban_seconds = 180};
    Core limiter(config);
    const auto key = Key(1);
    // Nine failures spread across the first window must not slide its start.
    for (unsigned i = 0; i < 5; ++i)
        limiter.OnAuthFailTracked(kTag, kIP, key, 100);
    for (unsigned i = 0; i < 4; ++i)
        limiter.OnAuthFailTracked(kTag, kIP, key, 159);
    EXPECT_FALSE(limiter.IsBanned(kTag, kIP, 159));
    EXPECT_EQ(limiter.CheckCredential(key, 159), Reason::NONE);

    limiter.OnAuthFailTracked(kTag, kIP, key, 160); // exact window boundary
    EXPECT_FALSE(limiter.IsBanned(kTag, kIP, 160));
    EXPECT_EQ(limiter.CheckCredential(key, 160), Reason::NONE);
    for (unsigned i = 0; i < 8; ++i)
        limiter.OnAuthFailTracked(kTag, kIP, key, 219);
    EXPECT_FALSE(limiter.IsBanned(kTag, kIP, 219));
    EXPECT_EQ(limiter.CheckCredential(key, 219), Reason::NONE);
    limiter.OnAuthFailTracked(kTag, kIP, key, 219);
    EXPECT_TRUE(limiter.IsBanned(kTag, kIP, 219));
    EXPECT_EQ(limiter.CheckCredential(key, 219), Reason::CREDENTIAL_BANNED);
    EXPECT_EQ(limiter.TryAcceptIP(kTag, kIP, true, 219), Reason::IP_BANNED);
    EXPECT_TRUE(limiter.IsBanned(kTag, kIP, 398));
    EXPECT_EQ(limiter.CheckCredential(key, 398), Reason::CREDENTIAL_BANNED);
    EXPECT_FALSE(limiter.IsBanned(kTag, kIP, 399));
    EXPECT_EQ(limiter.CheckCredential(key, 399), Reason::NONE);
}

TEST(BanTrackingContract, BannedFailuresNeverExtendExpiryOrAccumulate) {
    RateLimitConfig config;
    config.ip_ban = {.enabled = true, .failure_limit = 10,
                     .window_seconds = 60, .ban_seconds = 180};
    Core limiter(config);
    const auto key = Key(2);
    for (unsigned i = 0; i < 10; ++i)
        limiter.OnAuthFailTracked(kTag, kIP, key, 0); // epoch zero is a valid start
    for (unsigned i = 0; i < 20; ++i)
        limiter.OnAuthFailTracked(kTag, kIP, key, 179);
    EXPECT_TRUE(limiter.IsBanned(kTag, kIP, 179));
    EXPECT_EQ(limiter.CheckCredential(key, 179), Reason::CREDENTIAL_BANNED);
    EXPECT_FALSE(limiter.IsBanned(kTag, kIP, 180));
    EXPECT_EQ(limiter.CheckCredential(key, 180), Reason::NONE);
    for (unsigned i = 0; i < 9; ++i)
        limiter.OnAuthFailTracked(kTag, kIP, key, 180);
    EXPECT_FALSE(limiter.IsBanned(kTag, kIP, 180));
    EXPECT_EQ(limiter.CheckCredential(key, 180), Reason::NONE);
    limiter.OnAuthFailTracked(kTag, kIP, key, 180);
    EXPECT_TRUE(limiter.IsBanned(kTag, kIP, 180));
    EXPECT_EQ(limiter.CheckCredential(key, 180), Reason::CREDENTIAL_BANNED);
}

TEST(BanTrackingContract, MonotonicSecondsDoNotWrapAtUint32Boundary) {
    RateLimitConfig config;
    config.ip_ban = {.enabled = true, .failure_limit = 10,
                     .window_seconds = 60, .ban_seconds = 180};
    Core limiter(config);
    const auto key = Key(3);
    constexpr uint64_t now = static_cast<uint64_t>(std::numeric_limits<uint32_t>::max()) - 2;
    for (unsigned i = 0; i < 10; ++i)
        limiter.OnAuthFailTracked(kTag, kIP, key, now);
    EXPECT_TRUE(limiter.IsBanned(kTag, kIP, now + 179));
    EXPECT_EQ(limiter.CheckCredential(key, now + 179), Reason::CREDENTIAL_BANNED);
    EXPECT_FALSE(limiter.IsBanned(kTag, kIP, now + 180));
    EXPECT_EQ(limiter.CheckCredential(key, now + 180), Reason::NONE);
}

TEST(BanTrackingContract, TagsCredentialsAndIPRulesAreIndependent) {
    RateLimitConfig config;
    config.ip_ban = {.enabled = true, .failure_limit = 2,
                     .window_seconds = 60, .ban_seconds = 180};
    Core limiter(config);
    const auto key = Key(4);
    const auto other = Key(5);
    // One failed credential across ten source IPs reaches the credential limit;
    // no individual source reaches the independently configured IP threshold.
    for (unsigned i = 0; i < 10; ++i)
        limiter.OnAuthFailTracked(kTag, "192.0.2." + std::to_string(i + 1), key, 100);
    EXPECT_EQ(limiter.CheckCredential(key, 100), Reason::CREDENTIAL_BANNED);
    EXPECT_EQ(limiter.CheckCredential(other, 100), Reason::NONE);
    EXPECT_FALSE(limiter.IsBanned(kTag, kIP, 100));
    limiter.OnAuthFailTracked(kTag, kIP, std::nullopt, 100);
    EXPECT_TRUE(limiter.IsBanned(kTag, kIP, 100));
    EXPECT_FALSE(limiter.IsBanned(kOtherTag, kIP, 100));
    EXPECT_EQ(limiter.CheckCredential(other, 100), Reason::NONE);
    // An empty source must not consume an IP-ban slot or create an empty-IP ban.
    for (unsigned i = 0; i < 10; ++i)
        limiter.OnAuthFailTracked(kTag, {}, other, 100);
    EXPECT_FALSE(limiter.IsBanned(kTag, {}, 100));
    EXPECT_EQ(limiter.CheckCredential(other, 100), Reason::CREDENTIAL_BANNED);
}

TEST(BanTrackingContract, ExactCredentialKeysHaveIndependentFailureCounters) {
    RateLimitConfig config;
    config.ip_ban.enabled = false;
    Core limiter(config);
    AuthCredentialKey first{};
    AuthCredentialKey second{};
    second.back() = 1; // Identical prefixes are not sufficient to identify a key.
    for (unsigned i = 0; i < 9; ++i)
        limiter.OnAuthFailTracked(kTag, {}, first, 100);
    limiter.OnAuthFailTracked(kTag, {}, second, 100);
    EXPECT_EQ(limiter.CheckCredential(first, 100), Reason::NONE);
    EXPECT_EQ(limiter.CheckCredential(second, 100), Reason::NONE);
    limiter.OnAuthFailTracked(kTag, {}, first, 100);
    EXPECT_EQ(limiter.CheckCredential(first, 100), Reason::CREDENTIAL_BANNED);
    EXPECT_EQ(limiter.CheckCredential(second, 100), Reason::NONE);
}

TEST(BanTrackingContract, CredentialFingerprintUsesTagBinaryInputAndPrivateSalt) {
    net::io_context io, other_io;
    auto coordinator = std::make_shared<GroupCoordinator>(io);
    auto other_coordinator = std::make_shared<GroupCoordinator>(other_io);
    const RateLimitConfig config;
    auto limiter = ConnectionLimiter::Acquire(config, coordinator);
    auto other_limiter = ConnectionLimiter::Acquire(config, other_coordinator);
    const std::array<uint8_t, 3> credential{'a', 0, 'b'};
    const auto key = limiter->FingerprintCredential(kTag, credential, 1);

    Core core(config);
    for (unsigned i = 0; i < 10; ++i)
        core.OnAuthFailTracked(kTag, {}, key, 100);
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
        core.OnAuthFailTracked("a", {}, first_split, 100);
    EXPECT_EQ(core.CheckCredential(
        limiter->FingerprintCredential("ab", c, 1), 100), Reason::NONE);
    EXPECT_EQ(core.CheckCredential(limiter->FingerprintCredential(kOtherTag, credential, 1), 100),
              Reason::NONE);
    // Publishing a changed credential set invalidates the old negative cache,
    // while the old snapshot's key remains banned until its own expiry.
    const auto updated_key = limiter->FingerprintCredential(kTag, credential, 2);
    EXPECT_EQ(core.CheckCredential(updated_key, 100), Reason::NONE);
    core.OnAuthFailTracked(kTag, {}, updated_key, 100);
    EXPECT_EQ(core.CheckCredential(updated_key, 100), Reason::NONE);
    EXPECT_EQ(core.CheckCredential(key, 100), Reason::CREDENTIAL_BANNED);
}

TEST(BanTrackingContract, DisabledIPBanDoesNotAffectConnectionQuotas) {
    RateLimitConfig config;
    config.max_connections = 1;
    config.max_conn_per_ip = 1;
    config.ip_ban = {.enabled = false, .failure_limit = 1,
                     .window_seconds = 60, .ban_seconds = 180};
    Core limiter(config);
    EXPECT_FALSE(limiter.TracksAuthBan());
    for (unsigned i = 0; i < 10; ++i)
        limiter.OnAuthFailTracked(kTag, kIP, Key(6), 100);
    EXPECT_FALSE(limiter.IsBanned(kTag, kIP, 100));
    EXPECT_EQ(limiter.CheckCredential(Key(6), 100), Reason::CREDENTIAL_BANNED);
    EXPECT_EQ(limiter.TryAcceptGlobal(), Reason::NONE);
    EXPECT_EQ(limiter.TryAcceptIP(kTag, kIP, true, 100), Reason::NONE);
    EXPECT_EQ(limiter.TryAcceptIP(kTag, kIP, true, 100), Reason::MAX_CONNECTIONS_PER_IP);
    EXPECT_EQ(limiter.TryAcceptGlobal(), Reason::MAX_CONNECTIONS);
    limiter.ReleaseHash(Core::IpHash(kIP));
    EXPECT_EQ(limiter.TryAcceptGlobal(), Reason::MAX_CONNECTIONS);
    EXPECT_EQ(limiter.TryAcceptIP(kTag, kIP, true, 100), Reason::NONE);
    limiter.ReleaseHash(Core::IpHash(kIP));
    limiter.ReleaseGlobal();
    EXPECT_EQ(limiter.TryAcceptGlobal(), Reason::NONE);
    limiter.ReleaseGlobal();
}

TEST(BanTrackingContract, ExplicitIPBanBypassStillEnforcesConnectionQuota) {
    RateLimitConfig config;
    config.max_conn_per_ip = 1;
    config.ip_ban = {.enabled = true, .failure_limit = 1,
                     .window_seconds = 60, .ban_seconds = 180};
    Core limiter(config);
    limiter.OnAuthFailTracked(kTag, kIP, std::nullopt, 100);
    EXPECT_EQ(limiter.TryAcceptIP(kTag, kIP, true, 100), Reason::IP_BANNED);
    EXPECT_EQ(limiter.TryAcceptIP(kTag, kIP, false, 100), Reason::NONE);
    EXPECT_EQ(limiter.TryAcceptIP(kTag, kIP, false, 100), Reason::MAX_CONNECTIONS_PER_IP);
    limiter.ReleaseHash(Core::IpHash(kIP));
}

TEST(BanTrackingContract, DisabledIPOnlyOperationsSkipClosedMailbox) {
    net::io_context io;
    auto coordinator = std::make_shared<GroupCoordinator>(io);
    RateLimitConfig config;
    config.ip_ban.enabled = false;
    auto limiter = ConnectionLimiter::Acquire(config, coordinator);
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
    RateLimitConfig config;
    config.max_conn_per_ip = 1;
    config.ip_ban.enabled = false;
    Core limiter(config);
    std::vector<std::string> admitted;
    std::string rejected;
    for (unsigned value = 0; value <= Core::kSlotCount; ++value) {
        auto address = "198.18." + std::to_string(value >> 8) + "." +
                       std::to_string(value & 255);
        const auto reason = limiter.TryAcceptIP(kTag, address, true, 100);
        if (reason != Reason::NONE) {
            ASSERT_EQ(reason, Reason::TRACKING_CAPACITY);
            rejected = std::move(address);
            break;
        }
        admitted.push_back(std::move(address));
    }
    ASSERT_FALSE(rejected.empty());
    for (const auto& address : admitted) limiter.ReleaseHash(Core::IpHash(address));
    EXPECT_EQ(limiter.TryAcceptIP(kTag, rejected, true, 100), Reason::NONE);
    EXPECT_EQ(limiter.TryAcceptIP(kTag, rejected, true, 100), Reason::MAX_CONNECTIONS_PER_IP);
    limiter.ReleaseHash(Core::IpHash(rejected));
}

TEST(BanTrackingContract, CredentialQueriesDoNotInsertAndSaturationFailsClosedUntilExpiry) {
    RateLimitConfig config;
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
        limiter.OnAuthFailTracked(kTag, {}, Key(value), 100);
        ASSERT_EQ(limiter.CheckCredential(Key(value), 100), Reason::NONE);
    }
    ASSERT_LE(rejected, Core::kSlotCount);
    EXPECT_EQ(limiter.CheckCredential(Key(rejected), 159), Reason::TRACKING_CAPACITY);
    EXPECT_EQ(limiter.TryAcceptIP(kTag, kIP, true, 159), Reason::NONE);
    limiter.ReleaseHash(Core::IpHash(kIP)); // failure-table saturation consumes no quota
    EXPECT_EQ(limiter.CheckCredential(Key(rejected), 160), Reason::NONE);
    for (unsigned i = 0; i < 10; ++i)
        limiter.OnAuthFailTracked(kTag, {}, Key(rejected), 160);
    EXPECT_EQ(limiter.CheckCredential(Key(rejected), 160), Reason::CREDENTIAL_BANNED);
    EXPECT_EQ(limiter.CheckCredential(Key(rejected), 339), Reason::CREDENTIAL_BANNED);
    EXPECT_EQ(limiter.CheckCredential(Key(rejected), 340), Reason::NONE);
}

TEST(BanTrackingContract, IPFailureCapacityIsIndependentAndExpiredSlotsAreReusable) {
    RateLimitConfig config;
    config.max_conn_per_ip = 1;
    config.ip_ban = {.enabled = true, .failure_limit = 1,
                     .window_seconds = 60, .ban_seconds = 180};
    Core limiter(config);
    std::string rejected;
    for (unsigned value = 0; value <= Core::kSlotCount; ++value) {
        auto address = "198.19." + std::to_string(value >> 8) + "." +
                       std::to_string(value & 255);
        const auto reason = limiter.CheckIPBan(kTag, address, 100);
        if (reason == Reason::TRACKING_CAPACITY) {
            rejected = std::move(address);
            break;
        }
        ASSERT_EQ(reason, Reason::NONE);
        limiter.OnAuthFailTracked(kTag, address, std::nullopt, 100);
        ASSERT_TRUE(limiter.IsBanned(kTag, address, 100));
    }
    ASSERT_FALSE(rejected.empty());
    EXPECT_EQ(limiter.TryAcceptIP(kTag, rejected, true, 279), Reason::TRACKING_CAPACITY);
    EXPECT_EQ(limiter.CheckCredential(Key(7), 279), Reason::NONE);
    for (unsigned i = 0; i < 10; ++i)
        limiter.OnAuthFailTracked(kTag, {}, Key(7), 279);
    EXPECT_EQ(limiter.CheckCredential(Key(7), 279), Reason::CREDENTIAL_BANNED);
    EXPECT_EQ(limiter.TryAcceptIP(kTag, rejected, false, 279), Reason::NONE);
    limiter.ReleaseHash(Core::IpHash(rejected));
    EXPECT_EQ(limiter.CheckIPBan(kTag, rejected, 280), Reason::NONE);
    limiter.OnAuthFailTracked(kTag, rejected, std::nullopt, 280);
    EXPECT_EQ(limiter.TryAcceptIP(kTag, rejected, true, 280), Reason::IP_BANNED);
}
