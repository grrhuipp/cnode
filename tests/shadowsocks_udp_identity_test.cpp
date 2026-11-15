#include "shadowsocks_identity_fixture.hpp"
#include "common/allocator.hpp"
#include "proxy/shadowsocks/ss_udp.hpp"
#include <gtest/gtest.h>

namespace {
using namespace ss_identity_test;

class ShadowsocksUdpIdentity : public testing::Test {
protected:
    const common::TargetAddress target{"127.0.0.1", 443};
    const std::array<uint8_t, 5> payload{0x17, 0x29, 0x41, 0, 0xff};

    void TearDown() override { UserStore::ClearWorkerView(); }

    std::vector<uint8_t> Packet(const PreparedShadowsocksUser& user,
                                const proxy::SsCipherInfo& cipher, uint64_t packet_id = 0) {
        proxy::KeyBytes key;
        Require(key.assign(user.derived_key.span()));
        std::array<proxy::KeyBytes, 2> chain;
        std::span<const proxy::KeyBytes> psk_chain;
        if (!user.identity_key.empty()) {
            Require(chain[0].assign(user.identity_key.span()));
            chain[1] = key;
            psk_chain = chain;
        }
        proxy::Ss2022UdpSessionState state;
        Require(proxy::Init2022UdpSessionState(state, cipher, key));
        state.client_session_id = {0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde};
        state.next_packet_id = packet_id;
        const size_t size = proxy::Encode2022UdpRequestPacketTo(
            target, payload.data(), payload.size(), state, psk_chain, nullptr, 0);
        Require(size != 0);
        std::vector<uint8_t> packet(size);
        Require(proxy::Encode2022UdpRequestPacketTo(target, payload.data(), payload.size(),
            state, psk_chain, packet.data(), packet.size()) == size);
        return packet;
    }

    auto Decode(const std::vector<uint8_t>& packet,
                const UserStore::ShadowsocksUsersView& view,
                const proxy::SsCipherInfo& cipher) {
        return proxy::DecodeUdpPacket(packet.data(), packet.size(), view,
            cipher.type, cipher.key_size, cipher.salt_size);
    }

    void ExpectUser(const proxy::SsUdpDecodeResult& decoded,
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
        const auto bytes = decoded.payload.FrontSpan();
        std::vector<uint8_t> actual(bytes.begin(), bytes.end());
        EXPECT_EQ(actual, std::vector<uint8_t>(payload.begin(), payload.end()));
        const auto datagram = common::InspectUdpDatagram(decoded.payload);
        ASSERT_TRUE(datagram.Valid());
        EXPECT_TRUE(datagram.target->SameEndpoint(target));
        EXPECT_EQ(datagram.payload_size, payload.size());
    }
};

TEST_F(ShadowsocksUdpIdentity, EverySortedPositionAndGroupAuthenticates) {
    for (auto method : {"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm"}) {
        const auto cipher = *proxy::ParseCipherMethod(method);
        for (size_t groups : {0u, 1u, 4u, 19u}) {
            const auto users = Users(19, cipher, groups);
            Install(users);
            const auto view = UserStore::ShadowsocksUsers(kTag);
            UdpAssociations associations;
            // Visit every snapshot position, including each group's first,
            // middle and last hash; all users share session and packet IDs.
            for (size_t index = 0; index < view.size(); ++index) {
                const auto& user = users[view[index].profile.user_id - 1];
                auto packet = Packet(user, cipher);
                auto decoded = Decode(packet, view, cipher);
                ASSERT_TRUE(decoded);
                EXPECT_EQ(decoded->user_index, index);
                if (groups == 0) EXPECT_EQ(view[index].profile.user_id, users[index].profile.user_id);
                // The returned payload owns its storage, not the input packet.
                std::fill(packet.begin(), packet.end(), 0);
                ExpectUser(*decoded, view, user);
                EXPECT_TRUE(associations.Commit(*decoded));
                EXPECT_EQ(associations.Size(), index + 1);
                auto replayed = Decode(Packet(user, cipher), view, cipher);
                ASSERT_TRUE(replayed);
                EXPECT_FALSE(associations.Commit(*replayed));
            }
        }
    }
}

TEST_F(ShadowsocksUdpIdentity, HashCollisionsRequireFullPayloadAuthentication) {
    for (auto method : {"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm"}) {
        const auto cipher = *proxy::ParseCipherMethod(method);
        for (size_t chosen : {0u, 3u, 6u}) {
            auto users = Users(7, cipher);
            const auto hash = users[chosen].psk_hash;
            for (auto& user : users) user.psk_hash = hash;
            const auto expected = users[chosen];
            const auto packet = Packet(expected, cipher);
            Install(users);
            auto view = UserStore::ShadowsocksUsers(kTag);
            auto decoded = Decode(packet, view, cipher);
            ASSERT_TRUE(decoded);
            ExpectUser(*decoded, view, expected);

            users.erase(users.begin() + chosen);
            Install(users);
            view = UserStore::ShadowsocksUsers(kTag);
            EXPECT_FALSE(Decode(packet, view, cipher));
        }
    }
}

TEST_F(ShadowsocksUdpIdentity, MixedIdentityAndNonidentityCredentialsAuthenticate) {
    for (auto method : {"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm"}) {
        const auto cipher = *proxy::ParseCipherMethod(method);
        auto users = Users(15, cipher, 3);
        for (size_t i = 0; i < users.size(); i += 2) users[i].identity_key = {};
        std::reverse(users.begin(), users.end());
        Install(users);
        const auto view = UserStore::ShadowsocksUsers(kTag);
        UdpAssociations associations;
        for (const auto& user : users) {
            const auto packet = Packet(user, cipher);
            auto decoded = Decode(packet, view, cipher);
            ASSERT_TRUE(decoded);
            ExpectUser(*decoded, view, user);
            EXPECT_TRUE(associations.Commit(*decoded));
            EXPECT_FALSE(associations.Commit(*decoded));
        }
        EXPECT_EQ(associations.Size(), users.size());
    }
}

TEST_F(ShadowsocksUdpIdentity, RetiredSnapshotKeepsItsOwnCredentialsAndOrdering) {
    const auto cipher = *proxy::ParseCipherMethod("2022-blake3-aes-256-gcm");
    auto users = Users(13, cipher, 3);
    Install(users);
    const auto old_view = UserStore::ShadowsocksUsers(kTag);
    const auto retired = users[old_view[old_view.size() / 2].profile.user_id - 1];
    const auto old_packet = Packet(retired, cipher);
    for (auto& user : users) {
        user.derived_key.bytes[15] ^= 0x5a;
        Require(proxy::Hash2022Psk(user.derived_key.span(), user.psk_hash));
    }
    std::reverse(users.begin(), users.end());
    Install(users);
    const auto new_view = UserStore::ShadowsocksUsers(kTag);
    UserStore::ClearWorkerView();
    UdpAssociations associations;
    EXPECT_FALSE(Decode(old_packet, new_view, cipher));
    auto old_decoded = Decode(old_packet, old_view, cipher);
    ASSERT_TRUE(old_decoded);
    ExpectUser(*old_decoded, old_view, retired);
    EXPECT_TRUE(associations.Commit(*old_decoded));
    const auto replacement = std::find_if(users.begin(), users.end(), [&](const auto& user) {
        return user.profile.user_id == retired.profile.user_id;
    });
    ASSERT_NE(replacement, users.end());
    const auto new_packet = Packet(*replacement, cipher);
    EXPECT_FALSE(Decode(new_packet, old_view, cipher));
    auto new_decoded = Decode(new_packet, new_view, cipher);
    ASSERT_TRUE(new_decoded);
    ExpectUser(*new_decoded, new_view, *replacement);
    EXPECT_TRUE(associations.Commit(*new_decoded));
    EXPECT_EQ(associations.Size(), 2u);
    EXPECT_FALSE(associations.Commit(*old_decoded));
    EXPECT_FALSE(associations.Commit(*new_decoded));
}

TEST_F(ShadowsocksUdpIdentity, AuthenticationAloneLeavesAssociationReplayUntouched) {
    const auto cipher = *proxy::ParseCipherMethod("2022-blake3-aes-256-gcm");
    const auto users = Users(17, cipher, 3);
    Install(users);
    const auto view = UserStore::ShadowsocksUsers(kTag);
    const auto& user = users[view[view.size() - 1].profile.user_id - 1];
    UdpAssociations associations;
    for (uint64_t packet_id : {0u, 1u}) {
        const auto packet = Packet(user, cipher, packet_id);
        auto invalid = packet;
        invalid.back() ^= 1;
        EXPECT_FALSE(Decode(invalid, view, cipher));
        for (size_t attempt = 0; attempt < 2; ++attempt) {
            auto authenticated = Decode(packet, view, cipher);
            ASSERT_TRUE(authenticated);
            ExpectUser(*authenticated, view, user, packet_id);
        }
        auto accepted = Decode(packet, view, cipher);
        ASSERT_TRUE(accepted);
        ExpectUser(*accepted, view, user, packet_id);
        EXPECT_TRUE(associations.Commit(*accepted));
        EXPECT_EQ(associations.Size(), 1u);
        auto replayed = Decode(packet, view, cipher);
        ASSERT_TRUE(replayed);
        ExpectUser(*replayed, view, user, packet_id);
        EXPECT_FALSE(associations.Commit(*replayed));
        EXPECT_EQ(associations.Size(), 1u);
    }
}
} // namespace
