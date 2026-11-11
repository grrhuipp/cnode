#include <gtest/gtest.h>
#include "proxy/vless/vless_encryption.hpp"
#include <array>
#include <chrono>

namespace {
using namespace ::vless;
using namespace std::chrono_literals;
class VlessTicketStore : public testing::Test {
protected:
    const std::chrono::steady_clock::time_point now = std::chrono::steady_clock::time_point{} + 100s;
    std::array<uint8_t, 16> ticket{}, alice{}, bob{};
    VlessEncryptionPfsKey pfs;
    VlessEncryptionNfsKey nfs;
    VlessEncryptionServerTicketStore owner;
    void SetUp() override {
        bob[0] = 1;
        pfs.bytes[0] = 42;
        nfs.bytes[0] = 7;
        owner.Store(ticket, pfs, 60, now);
    }
};

TEST_F(VlessTicketStore, RequiresAuthenticationAndCannotReplaceIdentity) {
    EXPECT_FALSE(owner.Lookup(ticket, nfs, now));
    ASSERT_TRUE(owner.BindIdentity(ticket, alice, now));
    EXPECT_FALSE(owner.BindIdentity(ticket, bob, now));
    const auto accepted = owner.Lookup(ticket, nfs, now);
    ASSERT_TRUE(accepted);
    EXPECT_EQ(accepted->identity, alice);
    EXPECT_EQ(accepted->pfs_key.bytes[0], 42);
}

TEST_F(VlessTicketStore, RejectsReplayAndCrossInboundLookup) {
    ASSERT_TRUE(owner.BindIdentity(ticket, alice, now));
    ASSERT_TRUE(owner.Lookup(ticket, nfs, now));
    EXPECT_FALSE(owner.Lookup(ticket, nfs, now));
    VlessEncryptionServerTicketStore other;
    EXPECT_FALSE(other.Lookup(ticket, nfs, now));
}

TEST_F(VlessTicketStore, DuplicatePublicationPreservesReplayKeyAndOriginalExpiration) {
    ASSERT_TRUE(owner.BindIdentity(ticket, alice, now));
    ASSERT_TRUE(owner.Lookup(ticket, nfs, now));
    VlessEncryptionPfsKey replacement;
    replacement.bytes[0] = 99;
    owner.Store(ticket, replacement, 3600, now + 1s);
    EXPECT_FALSE(owner.Lookup(ticket, nfs, now + 1s));
    nfs.bytes[0] = 8;
    const auto accepted = owner.Lookup(ticket, nfs, now + 59s);
    ASSERT_TRUE(accepted);
    EXPECT_EQ(accepted->pfs_key.bytes[0], 42);
    nfs.bytes[0] = 9;
    EXPECT_FALSE(owner.Lookup(ticket, nfs, now + 60s));
    EXPECT_FALSE(owner.BindIdentity(ticket, alice, now + 60s));
}

TEST_F(VlessTicketStore, CapacityEvictionDoesNotResurrectOldTicket) {
    VlessEncryptionServerTicketStore bounded;
    for (size_t i = 0; i < 1025; ++i) {
        ticket[0] = static_cast<uint8_t>(i >> 8);
        ticket[1] = static_cast<uint8_t>(i);
        bounded.Store(ticket, pfs, 60, now);
        ASSERT_TRUE(bounded.BindIdentity(ticket, alice, now));
    }
    ticket = {};
    EXPECT_FALSE(bounded.Lookup(ticket, nfs, now));
}
}  // namespace
