#include "shadowsocks_identity_fixture.hpp"
#include "common/allocator.hpp"
#include "ss_udp.hpp"
#include <gtest/gtest.h>

namespace {
using namespace ss_identity_test;

class ShadowsocksUdpIdentity : public testing::Test {
protected:
    memory::AllocationDomain domain;
    memory::ScopedAllocationDomain lease{domain};
    const TargetAddress target{"127.0.0.1", 443};
    const std::array<uint8_t, 5> payload{0x17, 0x29, 0x41, 0, 0xff};

    void TearDown() override { UserStore::ClearWorkerView(); }

    std::vector<uint8_t> Packet(const PreparedShadowsocksUser& user,
                                const ss::SsCipherInfo& cipher, uint64_t packet_id = 0) {
        ss::KeyBytes key;
        Require(key.assign(user.derived_key.span()));
        std::array<ss::KeyBytes, 2> chain;
        std::span<const ss::KeyBytes> psk_chain;
        if (!user.identity_key.empty()) {
            Require(chain[0].assign(user.identity_key.span()));
            chain[1] = key;
            psk_chain = chain;
        }
        ss::Ss2022UdpSessionState state;
        Require(ss::Init2022UdpSessionState(state, cipher, key));
        state.client_session_id = {0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde};
        state.next_packet_id = packet_id;
        const size_t size = ss::Encode2022UdpRequestPacketTo(
            target, payload.data(), payload.size(), state, psk_chain, nullptr, 0);
        Require(size != 0);
        std::vector<uint8_t> packet(size);
        Require(ss::Encode2022UdpRequestPacketTo(target, payload.data(), payload.size(),
            state, psk_chain, packet.data(), packet.size()) == size);
        return packet;
    }

    static auto Decode(const std::vector<uint8_t>& packet,
                       const UserStore::ShadowsocksUsersView& view,
                       const ss::SsCipherInfo& cipher, ss::Ss2022UdpReplayCache& replay,
                       bool deferred = false) {
        return ss::DecodeUdpPacket(packet.data(), packet.size(), view,
            cipher.type, cipher.key_size, cipher.salt_size, replay, deferred);
    }

    void ExpectUser(const ss::SsUdpDecodeResult& decoded,
                    const UserStore::ShadowsocksUsersView& view,
                    const PreparedShadowsocksUser& user, uint64_t packet_id = 0) {
        ASSERT_LT(decoded.user_index, view.size());
        EXPECT_EQ(view[decoded.user_index].profile.user_id, user.profile.user_id);
        EXPECT_TRUE(decoded.target.SameEndpoint(target));
        EXPECT_EQ(decoded.session_id, 0x00123456789abcdeULL);
        EXPECT_EQ(decoded.packet_id, packet_id);
        ASSERT_EQ(decoded.session_owner.size, user.derived_key.size);
        EXPECT_TRUE(std::equal(user.derived_key.span().begin(), user.derived_key.span().end(),
                               decoded.session_owner.span().begin()));
        std::vector<uint8_t> actual;
        for (const auto* buffer : decoded.payload) {
            const auto bytes = buffer->Bytes();
            actual.insert(actual.end(), bytes.begin(), bytes.end());
        }
        EXPECT_EQ(actual, std::vector<uint8_t>(payload.begin(), payload.end()));
        const auto datagram = buf::InspectUdpDatagram(decoded.payload);
        ASSERT_TRUE(datagram.Valid());
        EXPECT_TRUE(datagram.target->SameEndpoint(target));
        EXPECT_EQ(datagram.payload_size, payload.size());
    }
};

TEST_F(ShadowsocksUdpIdentity, EverySortedPositionAndGroupAuthenticates) {
    for (auto method : {"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm"}) {
        const auto cipher = *ss::ParseCipherMethod(method);
        for (size_t groups : {0u, 1u, 4u, 19u}) {
            const auto users = Users(19, cipher, groups);
            Install(users);
            const auto view = UserStore::ShadowsocksUsers(kTag);
            ss::Ss2022UdpReplayCache replay;
            // Visit every snapshot position, including each group's first,
            // middle and last hash; all users share session and packet IDs.
            for (size_t index = 0; index < view.size(); ++index) {
                const auto& user = users[view[index].profile.user_id - 1];
                auto packet = Packet(user, cipher);
                auto decoded = Decode(packet, view, cipher, replay);
                ASSERT_TRUE(decoded);
                EXPECT_EQ(decoded->user_index, index);
                if (groups == 0) EXPECT_EQ(view[index].profile.user_id, users[index].profile.user_id);
                // The returned payload owns its storage, not the input packet.
                std::fill(packet.begin(), packet.end(), 0);
                ExpectUser(*decoded, view, user);
                EXPECT_EQ(replay.Size(), index + 1);
                EXPECT_FALSE(Decode(Packet(user, cipher), view, cipher, replay));
            }
        }
    }
}

TEST_F(ShadowsocksUdpIdentity, HashCollisionsRequireFullPayloadAuthentication) {
    for (auto method : {"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm"}) {
        const auto cipher = *ss::ParseCipherMethod(method);
        for (size_t chosen : {0u, 3u, 6u}) {
            auto users = Users(7, cipher);
            const auto hash = users[chosen].psk_hash;
            for (auto& user : users) user.psk_hash = hash;
            const auto expected = users[chosen];
            const auto packet = Packet(expected, cipher);
            Install(users);
            auto view = UserStore::ShadowsocksUsers(kTag);
            ss::Ss2022UdpReplayCache replay;
            auto decoded = Decode(packet, view, cipher, replay, true);
            ASSERT_TRUE(decoded);
            ExpectUser(*decoded, view, expected);
            EXPECT_EQ(replay.Size(), 0u);

            users.erase(users.begin() + chosen);
            Install(users);
            view = UserStore::ShadowsocksUsers(kTag);
            for (bool deferred : {false, true}) {
                EXPECT_FALSE(Decode(packet, view, cipher, replay, deferred));
                EXPECT_EQ(replay.Size(), 0u);
            }
        }
    }
}

TEST_F(ShadowsocksUdpIdentity, MixedIdentityAndNonidentityCredentialsAuthenticate) {
    for (auto method : {"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm"}) {
        const auto cipher = *ss::ParseCipherMethod(method);
        auto users = Users(15, cipher, 3);
        for (size_t i = 0; i < users.size(); i += 2) users[i].identity_key = {};
        std::reverse(users.begin(), users.end());
        Install(users);
        const auto view = UserStore::ShadowsocksUsers(kTag);
        ss::Ss2022UdpReplayCache replay;
        for (const auto& user : users) {
            const auto packet = Packet(user, cipher);
            auto decoded = Decode(packet, view, cipher, replay);
            ASSERT_TRUE(decoded);
            ExpectUser(*decoded, view, user);
            EXPECT_FALSE(Decode(packet, view, cipher, replay));
        }
        EXPECT_EQ(replay.Size(), users.size());
    }
}

TEST_F(ShadowsocksUdpIdentity, RetiredSnapshotKeepsItsOwnCredentialsAndOrdering) {
    const auto cipher = *ss::ParseCipherMethod("2022-blake3-aes-256-gcm");
    auto users = Users(13, cipher, 3);
    Install(users);
    const auto old_view = UserStore::ShadowsocksUsers(kTag);
    const auto retired = users[old_view[old_view.size() / 2].profile.user_id - 1];
    const auto old_packet = Packet(retired, cipher);
    for (auto& user : users) {
        user.derived_key.bytes[15] ^= 0x5a;
        Require(ss::Hash2022Psk(user.derived_key.span(), user.psk_hash));
    }
    std::reverse(users.begin(), users.end());
    Install(users);
    const auto new_view = UserStore::ShadowsocksUsers(kTag);
    UserStore::ClearWorkerView();
    ss::Ss2022UdpReplayCache replay;
    EXPECT_FALSE(Decode(old_packet, new_view, cipher, replay));
    EXPECT_EQ(replay.Size(), 0u);
    auto old_decoded = Decode(old_packet, old_view, cipher, replay);
    ASSERT_TRUE(old_decoded);
    ExpectUser(*old_decoded, old_view, retired);
    const auto replacement = std::find_if(users.begin(), users.end(), [&](const auto& user) {
        return user.profile.user_id == retired.profile.user_id;
    });
    ASSERT_NE(replacement, users.end());
    const auto new_packet = Packet(*replacement, cipher);
    EXPECT_FALSE(Decode(new_packet, old_view, cipher, replay));
    auto new_decoded = Decode(new_packet, new_view, cipher, replay);
    ASSERT_TRUE(new_decoded);
    ExpectUser(*new_decoded, new_view, *replacement);
    EXPECT_EQ(replay.Size(), 2u);
    EXPECT_FALSE(Decode(old_packet, old_view, cipher, replay));
    EXPECT_FALSE(Decode(new_packet, new_view, cipher, replay));
}

TEST_F(ShadowsocksUdpIdentity, DeferredAndInvalidAuthenticationLeaveReplayUntouched) {
    const auto cipher = *ss::ParseCipherMethod("2022-blake3-aes-256-gcm");
    const auto users = Users(17, cipher, 3);
    Install(users);
    const auto view = UserStore::ShadowsocksUsers(kTag);
    const auto& user = users[view[view.size() - 1].profile.user_id - 1];
    ss::Ss2022UdpReplayCache replay;
    for (uint64_t packet_id : {0u, 1u}) {
        const auto packet = Packet(user, cipher, packet_id);
        auto invalid = packet;
        invalid.back() ^= 1;
        for (bool deferred : {false, true}) {
            EXPECT_FALSE(Decode(invalid, view, cipher, replay, deferred));
            EXPECT_EQ(replay.Size(), packet_id == 0 ? 0u : 1u);
        }
        for (size_t attempt = 0; attempt < 2; ++attempt) {
            auto authenticated = Decode(packet, view, cipher, replay, true);
            ASSERT_TRUE(authenticated);
            ExpectUser(*authenticated, view, user, packet_id);
            EXPECT_EQ(replay.Size(), packet_id == 0 ? 0u : 1u);
        }
        auto accepted = Decode(packet, view, cipher, replay);
        ASSERT_TRUE(accepted);
        ExpectUser(*accepted, view, user, packet_id);
        EXPECT_EQ(replay.Size(), 1u);
        EXPECT_FALSE(Decode(packet, view, cipher, replay));
        auto deferred_replay = Decode(packet, view, cipher, replay, true);
        ASSERT_TRUE(deferred_replay);
        ExpectUser(*deferred_replay, view, user, packet_id);
        EXPECT_EQ(replay.Size(), 1u);
        EXPECT_FALSE(Decode(packet, view, cipher, replay));
    }
}
} // namespace
