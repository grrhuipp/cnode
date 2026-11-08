#include "shadowsocks_identity_fixture.hpp"
#include "common/allocator.hpp"
#include "ss_udp.hpp"
#include <gtest/gtest.h>
#include <limits>

namespace {
using namespace ss_identity_test;
class ShadowsocksIdentity : public testing::Test {
protected:
    memory::AllocationDomain domain;
    memory::ScopedAllocationDomain lease{domain};
    net::io_context io;
    void TearDown() override { UserStore::ClearWorkerView(); }
};

TEST_F(ShadowsocksIdentity, EveryGroupAndHintAuthenticatesItsOwnUser) {
    for (auto method : {"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm"}) {
        const auto cipher = *ss::ParseCipherMethod(method);
        for (size_t groups : {0u, 1u, 4u}) {
            auto users = Users(19, cipher, groups);
            Install(users);
            size_t hint = std::numeric_limits<size_t>::max();
            for (size_t index : {0u, 18u, 9u, 18u, 0u}) {
                Wire wire;
                Prepare(io, wire, users[index], cipher);
                auto result = Authenticate(io, wire, cipher, hint);
                ASSERT_TRUE(result);
                EXPECT_EQ(result->user->profile.user_id, users[index].profile.user_id);
                EXPECT_EQ(result->target.port, 443);
                const auto view = UserStore::ShadowsocksUsers(kTag);
                ASSERT_LT(hint, view.size());
                EXPECT_EQ(view[hint].profile.user_id, users[index].profile.user_id);
                if (groups == 0) EXPECT_EQ(hint, index);
                auto hinted = Authenticate(io, wire, cipher, hint);
                ASSERT_TRUE(hinted);
                EXPECT_EQ(hinted->user->profile.user_id, users[index].profile.user_id);
            }
        }
    }
}

TEST_F(ShadowsocksIdentity, HashCollisionStillRequiresFixedHeaderAuthentication) {
    const auto cipher = *ss::ParseCipherMethod("2022-blake3-aes-128-gcm");
    auto users = Users(7, cipher);
    // Exercise a candidate collision without relying on finding a BLAKE3 collision.
    // The prepared snapshot is the public authentication input contract.
    for (auto& user : users) user.psk_hash = users[4].psk_hash;
    Install(users);
    Wire wire;
    Prepare(io, wire, users[4], cipher);
    for (size_t hint = 0; hint < users.size(); ++hint) {
        size_t current_hint = hint;
        auto result = Authenticate(io, wire, cipher, current_hint);
        ASSERT_TRUE(result);
        EXPECT_EQ(result->user->profile.user_id, users[4].profile.user_id);
    }
    users.erase(users.begin() + 4);
    Install(users);
    size_t hint = 0;
    auto rejected = Authenticate(io, wire, cipher, hint);
    ASSERT_FALSE(rejected);
    EXPECT_EQ(rejected.error(), ErrorCode::PROTOCOL_AUTH_FAILED);
}

TEST_F(ShadowsocksIdentity, LastGroupHintMissAndCollisionPreserveAuthentication) {
    const auto cipher = *ss::ParseCipherMethod("2022-blake3-aes-128-gcm");
    auto users = Users(12, cipher, 3);
    for (size_t i = 2; i < users.size(); i += 3) users[i].psk_hash = users[11].psk_hash;
    Install(users);
    Wire wire;
    Prepare(io, wire, users[11], cipher);
    const auto view = UserStore::ShadowsocksUsers(kTag);
    // Include hints in other groups, colliding candidates in the final group,
    // the authenticated user itself, and the absent-hint path.
    for (size_t initial_hint = 0; initial_hint <= view.size(); ++initial_hint) {
        size_t hint = initial_hint;
        auto result = Authenticate(io, wire, cipher, hint);
        ASSERT_TRUE(result);
        EXPECT_EQ(result->user->profile.user_id, users[11].profile.user_id);
        EXPECT_EQ(view[hint].profile.user_id, users[11].profile.user_id);
        auto repeated = Authenticate(io, wire, cipher, hint);
        ASSERT_TRUE(repeated);
        EXPECT_EQ(repeated->user->profile.user_id, users[11].profile.user_id);
    }
}

TEST_F(ShadowsocksIdentity, SnapshotReplacementRetainsOldOwnershipNotOldHints) {
    const auto cipher = *ss::ParseCipherMethod("2022-blake3-aes-256-gcm");
    auto users = Users(17, cipher, 3);
    Install(users);
    Wire wire;
    Prepare(io, wire, users[16], cipher);
    size_t hint = 0;
    auto old = Authenticate(io, wire, cipher, hint);
    ASSERT_TRUE(old);
    const auto old_view = UserStore::ShadowsocksUsers(kTag);
    auto replacement = PreparedShadowsocksUsers{users[16], users[0]};
    replacement[0].profile.user_id = 701;
    Install(replacement);
    auto current = Authenticate(io, wire, cipher, hint);
    ASSERT_TRUE(current);
    EXPECT_EQ(current->user->profile.user_id, 701);
    EXPECT_EQ(old->user->profile.user_id, 17);
    EXPECT_EQ(old_view.size(), 17u);
    Install(PreparedShadowsocksUsers{users[0]});
    EXPECT_FALSE(Authenticate(io, wire, cipher, hint));
    EXPECT_EQ(old->user->profile.user_id, 17);
}

TEST_F(ShadowsocksIdentity, InvalidCredentialCannotBorrowAnotherUsersIdentity) {
    const auto cipher = *ss::ParseCipherMethod("2022-blake3-aes-128-gcm");
    auto users = Users(5, cipher, 2);
    const auto client = users[2];
    Wire wire;
    Prepare(io, wire, client, cipher);
    users[2].derived_key.size = 0;
    Install(users);
    size_t hint = 2;
    EXPECT_FALSE(Authenticate(io, wire, cipher, hint));
    users = Users(5, cipher, 2);
    users[2].identity_key.bytes[0] ^= 0x40;
    Install(users);
    EXPECT_FALSE(Authenticate(io, wire, cipher, hint));
}

TEST_F(ShadowsocksIdentity, DuplicateCredentialsFailBeforePublication) {
    const auto cipher = *ss::ParseCipherMethod("2022-blake3-aes-128-gcm");
    auto users = Users(4, cipher, 2);
    Install(users);
    const auto before = UserStore::ShadowsocksUsers(kTag);
    users.push_back(users[0]);
    users.back().profile.user_id = 99;
    EXPECT_THROW(Install(users), std::invalid_argument);
    EXPECT_EQ(UserStore::ShadowsocksUsers(kTag).users.get(), before.users.get());
}

TEST_F(ShadowsocksIdentity, InvalidPreparedIdentityLengthDoesNotReplaceSnapshot) {
    const auto cipher = *ss::ParseCipherMethod("2022-blake3-aes-128-gcm");
    auto users = Users(4, cipher);
    Install(users);
    const auto before = UserStore::ShadowsocksUsers(kTag);
    users.back().identity_key.size = PreparedKeyBytes::kMaxSize + 1;
    EXPECT_THROW(Install(users), std::invalid_argument);
    EXPECT_EQ(UserStore::ShadowsocksUsers(kTag).users.get(), before.users.get());
}

TEST_F(ShadowsocksIdentity, SortedSnapshotPreservesUdpOwnerAndReplayIsolation) {
    const auto cipher = *ss::ParseCipherMethod("2022-blake3-aes-128-gcm");
    const auto users = Users(17, cipher, 3);
    Install(users);
    const auto view = UserStore::ShadowsocksUsers(kTag);
    ss::Ss2022UdpReplayCache replay;
    for (size_t index : {0u, 8u, 16u}) {
        ss::KeyBytes key;
        ASSERT_TRUE(key.assign(users[index].derived_key.span()));
        std::array<ss::KeyBytes, 2> chain;
        ASSERT_TRUE(chain[0].assign(users[index].identity_key.span()));
        chain[1] = key;
        ss::Ss2022UdpSessionState state;
        ASSERT_TRUE(ss::Init2022UdpSessionState(state, cipher, key));
        state.client_session_id = {1, 2, 3, 4, 5, 6, 7, 8};
        const TargetAddress target("127.0.0.1", 443);
        const std::array<uint8_t, 3> payload{1, 2, 3};
        const auto size = ss::Encode2022UdpRequestPacketTo(
            target, payload.data(), payload.size(), state, chain, nullptr, 0);
        std::vector<uint8_t> packet(size);
        ASSERT_EQ(ss::Encode2022UdpRequestPacketTo(target, payload.data(), payload.size(),
            state, chain, packet.data(), packet.size()), size);
        auto result = ss::DecodeUdpPacket(packet.data(), packet.size(), view,
            cipher.type, cipher.key_size, cipher.salt_size, replay);
        ASSERT_TRUE(result);
        ASSERT_LT(result->user_index, view.size());
        EXPECT_EQ(view[result->user_index].profile.user_id, users[index].profile.user_id);
        EXPECT_FALSE(ss::DecodeUdpPacket(packet.data(), packet.size(), view,
            cipher.type, cipher.key_size, cipher.salt_size, replay));
    }
}
} // namespace
