#include <stdexcept>
#include <gtest/gtest.h>

#include "proxy/shadowsocks/ss_udp.hpp"
#include "proxy/shadowsocks/ss_stream.hpp"
#include "proxy/shadowsocks/shadowsocks_protocol.hpp"
#include <asio/bind_cancellation_slot.hpp>
#include <asio/cancellation_signal.hpp>
#include <asio/co_spawn.hpp>
#include <asio/post.hpp>
#include <asio/redirect_error.hpp>
#include <asio/steady_timer.hpp>
#include <asio/use_future.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <memory>
#include <string_view>
#include <tuple>
#include <vector>

namespace {



std::vector<uint8_t> Flatten(const buf::MultiBuffer& payload) {
    std::vector<uint8_t> out;
    out.reserve(payload.byte_size());
    for (const buf::Buffer* buffer : payload) {
        if (!buffer || buffer->IsEmpty()) {
            continue;
        }
        const auto bytes = buffer->Bytes();
        out.insert(out.end(), bytes.begin(), bytes.end());
    }
    return out;
}

buf::MultiBuffer MakePayload(const std::vector<uint8_t>& source,
                             const TargetAddress& target) {
    buf::MultiBuffer payload;
    EXPECT_TRUE((buf::AppendSpanToMultiBuffer(source, payload))) << "failed to allocate Shadowsocks UDP test payload";
    EXPECT_TRUE((buf::SetUdpTarget(payload, target))) << "failed to mark Shadowsocks UDP test datagram";
    return payload;
}

void CheckClassic(const TargetAddress& target,
                  const std::vector<uint8_t>& source,
                  std::span<const uint8_t> payload,
                  const ss::SsCipherInfo& cipher) {
    const ss::KeyBytes key = ss::DeriveKey("udp-datagram-test", cipher.key_size);
    const size_t encoded_size = ss::EncodeUdpPacketTo(
        target, payload.data(), payload.size(), key.span(),
        cipher.type, cipher.key_size, cipher.salt_size, nullptr, 0);
    std::vector<uint8_t> encoded(encoded_size);
    EXPECT_EQ((ss::EncodeUdpPacketTo(
              target, payload.data(), payload.size(), key.span(),
              cipher.type, cipher.key_size - 1, cipher.salt_size,
              encoded.data(), encoded.size())), (0)) << "datagram AEAD accepted an incompatible encryption key length";
    EXPECT_EQ((ss::EncodeUdpPacketTo(
              target, payload.data(), payload.size(), key.span(),
              cipher.type, cipher.key_size, cipher.salt_size,
              encoded.data(), encoded.size())), (encoded.size())) << "classic Shadowsocks UDP encoding failed";
    EXPECT_FALSE((ss::DecodeUdpPacketWithKey(
              encoded.data(), encoded.size(), key.span(),
              cipher.type, cipher.key_size - 1, cipher.salt_size))) << "datagram AEAD accepted an incompatible decryption key length";

    auto decoded = ss::DecodeUdpPacketWithKey(
        encoded.data(), encoded.size(), key.span(),
        cipher.type, cipher.key_size, cipher.salt_size);
    ASSERT_TRUE(decoded);
    EXPECT_TRUE((decoded && decoded->target.SameEndpoint(target) &&
          Flatten(decoded->payload) == source)) << "classic Shadowsocks split one MultiBuffer datagram";
    EXPECT_FALSE((decoded->session_id)) << "classic UDP unexpectedly supplied a protocol session ID";
    EXPECT_FALSE((decoded->packet_id)) << "classic UDP unexpectedly supplied an authenticated packet ID";
    const auto reply_datagram = buf::InspectUdpDatagram(decoded->payload);
    EXPECT_TRUE((reply_datagram.Valid() && reply_datagram.target->SameEndpoint(target) &&
          reply_datagram.payload_size == source.size())) << "classic Shadowsocks reply lost its UDP message boundary";

    auto user_list = std::make_shared<
        proxyman::inbound::UserStore::ShadowsocksUserList>();
    proxyman::inbound::UserStore::ShadowsocksCredential user;
    EXPECT_TRUE((user.derived_key.assign(key.span()))) << "failed to prepare classic UDP user";
    user_list->push_back(std::move(user));
    ss::Ss2022UdpReplayCache replay_cache;
    for (bool deferred_replay : {false, true}) {
        auto inbound = ss::DecodeUdpPacket(
            encoded.data(), encoded.size(), {user_list},
            cipher.type, cipher.key_size, cipher.salt_size, replay_cache, deferred_replay);
        ASSERT_TRUE(inbound);
        EXPECT_TRUE((inbound && !inbound->session_id && !inbound->packet_id &&
              inbound->target.SameEndpoint(target) && Flatten(inbound->payload) == source &&
              replay_cache.Size() == 0)) << "deferred replay changed classic UDP decoding";
        const auto request_datagram = buf::InspectUdpDatagram(inbound->payload);
        EXPECT_TRUE((request_datagram.Valid() && request_datagram.target->SameEndpoint(target) &&
              request_datagram.payload_size == source.size())) << "classic authenticated request lost its UDP message boundary";
    }

    EXPECT_TRUE((!ss::DecodeUdpPacket(nullptr, 0, {user_list}, cipher.type,
                              cipher.key_size, cipher.salt_size, replay_cache, false) &&
          !ss::DecodeUdpPacketWithKey(nullptr, 0, key.span(), cipher.type,
                                     cipher.key_size, cipher.salt_size))) << "raw empty Shadowsocks wire bypassed authentication";
    // Cross-check the one-shot AEAD API against the existing streaming EVP
    // implementation, rather than only round-tripping through the new path.
    std::array<uint8_t, 32> subkey{};
    std::array<uint8_t, 12> nonce{};
    EXPECT_TRUE((ss::DeriveSubkey(key.data(), key.size, encoded.data(), cipher.salt_size,
                          subkey.data()))) << "reference subkey derivation failed";
    ss::SsAeadCipher reference(cipher.type, subkey.data(), cipher.key_size);
    const auto body = std::span<const uint8_t>(encoded).subspan(cipher.salt_size);
    std::vector<uint8_t> plaintext(body.size() - ss::SsAeadCipher::kTagSize);
    EXPECT_TRUE((reference.Decrypt(nonce.data(), body.data(), body.size(), plaintext.data()))) << "EVP could not decrypt one-shot AEAD ciphertext";
    EXPECT_TRUE((std::equal(source.begin(), source.end(), plaintext.end() - source.size()))) << "reference AEAD plaintext mismatch";
    std::vector<uint8_t> reference_ciphertext(body.size());
    ss::SsAeadCipher encoder(cipher.type, subkey.data(), cipher.key_size);
    EXPECT_TRUE((encoder.Encrypt(nonce.data(), plaintext.data(), plaintext.size(), reference_ciphertext.data()) &&
          std::equal(body.begin(), body.end(), reference_ciphertext.begin()))) << "AEAD ciphertext/tag differ from streaming EVP";
    encoded.back() ^= 1;
    EXPECT_FALSE((ss::DecodeUdpPacketWithKey(encoded.data(), encoded.size(), key.span(),
                                    cipher.type, cipher.key_size, cipher.salt_size))) << "datagram AEAD accepted a modified tag";
}

void Check2022(const TargetAddress& target,
               const std::vector<uint8_t>& source,
               std::span<const uint8_t> payload,
               ss::SsCipherType cipher_type,
               size_t key_size,
               bool identity) {
    const ss::SsCipherInfo cipher{cipher_type, key_size, key_size};
    ss::KeyBytes key;
    std::array<uint8_t, 32> key_bytes{};
    for (size_t i = 0; i < key_size; ++i) {
        key_bytes[i] = static_cast<uint8_t>(i + 1);
    }
    EXPECT_TRUE((key.assign(std::span<const uint8_t>(key_bytes).first(key_size)))) << "failed to initialize Shadowsocks 2022 key";

    std::array<ss::KeyBytes, 2> chain{};
    std::span<const ss::KeyBytes> psk_chain;
    if (identity) {
        auto identity_bytes = key_bytes;
        for (auto& byte : identity_bytes) byte ^= 0xa5;
        EXPECT_TRUE((chain[0].assign(std::span<const uint8_t>(identity_bytes).first(key_size)))) << "failed to initialize identity key";
        chain[1] = key;
        psk_chain = chain;
    }
    ss::Ss2022UdpSessionState encoder;
    EXPECT_TRUE((ss::Init2022UdpSessionState(encoder, cipher, key))) << "failed to initialize Shadowsocks 2022 UDP state";
    encoder.client_session_id = {0x00, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde};
    const size_t encoded_size = ss::Encode2022UdpRequestPacketTo(
        target, payload.data(), payload.size(), encoder, psk_chain, nullptr, 0);
    EXPECT_EQ((encoder.next_packet_id), (0)) << "Shadowsocks 2022 size calculation advanced packet state";
    std::vector<uint8_t> encoded(encoded_size);
    EXPECT_EQ((ss::Encode2022UdpRequestPacketTo(
              target, payload.data(), payload.size(), encoder, psk_chain,
              encoded.data(), encoded.size())), (encoded.size())) << "Shadowsocks 2022 UDP encoding failed";
    EXPECT_EQ((encoder.next_packet_id), (1)) << "Shadowsocks 2022 request did not advance packet state once";

    proxyman::inbound::PreparedShadowsocksUsers prepared_users;
    proxyman::inbound::PreparedShadowsocksUser user;
    EXPECT_TRUE((user.derived_key.assign(key.span()))) << "failed to initialize Shadowsocks 2022 decode user";
    if (identity) {
        EXPECT_TRUE((user.identity_key.assign(chain[0].span()) &&
              ss::Hash2022Psk(key.span(), user.psk_hash))) << "failed to prepare identity credential";
    }
    if (identity) {
        auto decoy = user;
        decoy.derived_key.bytes[0] ^= 0x5a;
        EXPECT_TRUE((ss::Hash2022Psk(decoy.derived_key.span(), decoy.psk_hash))) << "failed to prepare decoy credential";
        auto other_identity = decoy;
        other_identity.identity_key.bytes[0] ^= 0x33;
        other_identity.derived_key.bytes[1] ^= 0x33;
        EXPECT_TRUE((ss::Hash2022Psk(other_identity.derived_key.span(), other_identity.psk_hash))) << "failed to prepare other identity credential";
        prepared_users.push_back(std::move(other_identity));
        prepared_users.push_back(std::move(decoy));
    }
    prepared_users.push_back(std::move(user));
    const auto prepare_view = [](const proxyman::inbound::PreparedShadowsocksUsers& prepared) {
        using proxyman::inbound::UserStore;
        constexpr std::string_view tag = "ss-udp-datagram-test";
        UserStore::InstallWorkerView(UserStore::PrepareWorkerView(
            UserStore::PrepareUsers(tag, proxyman::inbound::UserSet{prepared})));
        auto view = UserStore::ShadowsocksUsers(tag);
        UserStore::ClearWorkerView();
        return view;
    };
    const auto users = prepare_view(prepared_users);
    if (identity) {
        auto bad_prepared = prepared_users;
        bad_prepared.back().psk_hash[0] ^= 1;
        const auto bad_users = prepare_view(bad_prepared);
        ss::Ss2022UdpReplayCache bad_cache;
        EXPECT_FALSE((ss::DecodeUdpPacket(encoded.data(), encoded.size(), bad_users,
                                  cipher.type, cipher.key_size, cipher.salt_size, bad_cache, false))) << "identity authentication ignored prepared PSK hash";
        EXPECT_TRUE((!ss::DecodeUdpPacket(encoded.data(), encoded.size(), bad_users,
                                  cipher.type, cipher.key_size, cipher.salt_size, bad_cache, true) &&
              bad_cache.Size() == 0)) << "deferred identity authentication accepted an invalid PSK hash or mutated replay";
    }
    std::vector<uint8_t> corrupted = encoded;
    corrupted.back() ^= 0x01;
    ss::Ss2022UdpReplayCache validation_cache;
    EXPECT_FALSE((ss::DecodeUdpPacket(
              corrupted.data(), corrupted.size(), users,
              cipher.type, cipher.key_size, cipher.salt_size,
              validation_cache, false))) << "invalid Shadowsocks 2022 request unexpectedly decoded";
    EXPECT_EQ((validation_cache.Size()), (0)) << "invalid Shadowsocks 2022 authentication created replay state";
    EXPECT_TRUE((!ss::DecodeUdpPacket(
              corrupted.data(), corrupted.size(), users,
              cipher.type, cipher.key_size, cipher.salt_size, validation_cache, true) &&
          validation_cache.Size() == 0)) << "deferred invalid authentication accepted ciphertext or mutated replay";
    EXPECT_TRUE((!ss::DecodeUdpPacket(nullptr, 0, users, cipher.type, cipher.key_size,
                              cipher.salt_size, validation_cache, false) &&
          validation_cache.Size() == 0)) << "raw empty SS2022 wire bypassed authentication or created replay state";
    EXPECT_TRUE((ss::DecodeUdpPacket(
              encoded.data(), encoded.size(), users,
              cipher.type, cipher.key_size, cipher.salt_size,
              validation_cache, false).has_value())) << "invalid Shadowsocks 2022 request poisoned the replay window";

    ss::Ss2022UdpReplayCache replay_cache;
    for (size_t attempt = 0; attempt < 2; ++attempt) {
        auto authenticated = ss::DecodeUdpPacket(
            encoded.data(), encoded.size(), users,
            cipher.type, cipher.key_size, cipher.salt_size, replay_cache, true);
        EXPECT_TRUE((authenticated && authenticated->session_id == 0x00123456789abcdeULL &&
              authenticated->packet_id == 0 &&
              authenticated->session_owner.size == key.size &&
              std::equal(key.span().begin(), key.span().end(),
                         authenticated->session_owner.span().begin()) &&
              authenticated->target.SameEndpoint(target) &&
              Flatten(authenticated->payload) == source && replay_cache.Size() == 0)) << "SS2022 authentication lost metadata or committed replay";
    }
    auto decoded = ss::DecodeUdpPacket(
        encoded.data(), encoded.size(), users,
        cipher.type, cipher.key_size, cipher.salt_size, replay_cache, false);
    ASSERT_TRUE(decoded);
    EXPECT_TRUE((decoded && decoded->target.SameEndpoint(target) &&
          Flatten(decoded->payload) == source)) << "Shadowsocks 2022 split one MultiBuffer datagram";
    const auto request_datagram = buf::InspectUdpDatagram(decoded->payload);
    EXPECT_TRUE((request_datagram.Valid() && request_datagram.target->SameEndpoint(target) &&
          request_datagram.payload_size == source.size())) << "SS2022 authenticated request lost its UDP message boundary";
    EXPECT_EQ((decoded->session_id), (0x00123456789abcdeULL)) << "Shadowsocks 2022 session ID lost byte order or leading zeros";
    EXPECT_TRUE((decoded->packet_id == 0 && decoded->session_owner.size == key.size &&
          std::equal(key.span().begin(), key.span().end(), decoded->session_owner.span().begin()))) << "SS2022 decode lost authenticated packet ID or full credential";
    EXPECT_FALSE((ss::DecodeUdpPacket(
              encoded.data(), encoded.size(), users,
              cipher.type, cipher.key_size, cipher.salt_size, replay_cache, false))) << "Shadowsocks 2022 accepted a replayed request packet";
    auto authenticated_replay = ss::DecodeUdpPacket(
        encoded.data(), encoded.size(), users,
        cipher.type, cipher.key_size, cipher.salt_size, replay_cache, true);
    ASSERT_TRUE(authenticated_replay);
    ASSERT_TRUE(authenticated_replay->session_id);
    ASSERT_TRUE(authenticated_replay->packet_id);
    EXPECT_TRUE((authenticated_replay && replay_cache.Size() == 1)) << "deferred authentication consulted already committed replay state";
    std::array<uint8_t, 8> authenticated_session{};
    for (size_t i = 0; i < authenticated_session.size(); ++i) {
        authenticated_session[i] = static_cast<uint8_t>(
            *authenticated_replay->session_id >> ((authenticated_session.size() - 1 - i) * 8));
    }
    ss::Ss2022UdpReplayCache ingress_replay;
    EXPECT_TRUE((ingress_replay.Accept(authenticated_replay->session_owner.span(),
                               authenticated_session, *authenticated_replay->packet_id) &&
          !ingress_replay.Accept(authenticated_replay->session_owner.span(),
                                authenticated_session, *authenticated_replay->packet_id))) << "authenticated metadata did not support a unique external replay commit";

    // A forged high packet ID must not advance an already initialized window.
    constexpr uint64_t kHighPacketId = 0x0102030405060708ULL;
    encoder.next_packet_id = kHighPacketId;
    std::vector<uint8_t> high_packet(encoded_size);
    EXPECT_EQ((ss::Encode2022UdpRequestPacketTo(
              target, payload.data(), payload.size(), encoder, psk_chain,
              high_packet.data(), high_packet.size())), (high_packet.size())) << "failed to encode high packet ID";
    high_packet.back() ^= 1;
    for (bool deferred_replay : {false, true}) {
        EXPECT_TRUE((!ss::DecodeUdpPacket(
                  high_packet.data(), high_packet.size(), users,
                  cipher.type, cipher.key_size, cipher.salt_size, replay_cache, deferred_replay) &&
              replay_cache.Size() == 1)) << "invalid authentication changed an existing replay namespace";
    }
    encoder.next_packet_id = 1;
    std::vector<uint8_t> next_packet(encoded_size);
    EXPECT_EQ((ss::Encode2022UdpRequestPacketTo(
              target, payload.data(), payload.size(), encoder, psk_chain,
              next_packet.data(), next_packet.size())), (next_packet.size())) << "failed to encode next packet ID";
    auto next_decoded = ss::DecodeUdpPacket(
        next_packet.data(), next_packet.size(), users,
        cipher.type, cipher.key_size, cipher.salt_size, replay_cache, false);
    EXPECT_TRUE((next_decoded && next_decoded->packet_id == 1)) << "invalid authentication advanced the replay window";
    high_packet.back() ^= 1;
    auto high_authenticated = ss::DecodeUdpPacket(
        high_packet.data(), high_packet.size(), users,
        cipher.type, cipher.key_size, cipher.salt_size, replay_cache, true);
    EXPECT_TRUE((high_authenticated && high_authenticated->packet_id == kHighPacketId)) << "SS2022 authenticated packet ID lost width or byte order";
    EXPECT_FALSE((ss::DecodeUdpPacket(
              next_packet.data(), next_packet.size(), users,
              cipher.type, cipher.key_size, cipher.salt_size, replay_cache, false))) << "deferred authentication cleared existing replay history";
    // Distinct authenticated users may independently choose identical session
    // and packet IDs. Authentication must scope the replay window too.
    ss::KeyBytes second_key = key;
    second_key.bytes[second_key.size - 1] ^= 0x5a;
    auto second_user = prepared_users.back();
    EXPECT_TRUE((second_user.derived_key.assign(second_key.span()))) << "failed to prepare second user's key";
    if (identity)
        EXPECT_TRUE((ss::Hash2022Psk(second_key.span(), second_user.psk_hash))) << "failed to prepare second identity credential";
    prepared_users.push_back(std::move(second_user));
    const auto second_users = prepare_view(prepared_users);
    ss::Ss2022UdpSessionState second_encoder;
    EXPECT_TRUE((ss::Init2022UdpSessionState(second_encoder, cipher, second_key))) << "failed to prepare second user's UDP session";
    second_encoder.client_session_id = encoder.client_session_id;
    if (identity) chain[1] = second_key;
    const size_t second_size = ss::Encode2022UdpRequestPacketTo(
        target, payload.data(), payload.size(), second_encoder, psk_chain, nullptr, 0);
    std::vector<uint8_t> second_packet(second_size);
    EXPECT_TRUE((second_size != 0 && ss::Encode2022UdpRequestPacketTo(
              target, payload.data(), payload.size(), second_encoder, psk_chain,
              second_packet.data(), second_packet.size()) == second_size)) << "failed to encode second user's UDP packet";
    auto second_decoded = ss::DecodeUdpPacket(
        second_packet.data(), second_packet.size(), second_users,
        cipher.type, cipher.key_size, cipher.salt_size, replay_cache, false);
    EXPECT_TRUE((second_decoded && second_decoded->session_id == decoded->session_id &&
          !std::equal(decoded->session_owner.span().begin(), decoded->session_owner.span().end(),
                      second_decoded->session_owner.span().begin()) &&
          Flatten(second_decoded->payload) == source)) << "SS2022 replay state crossed authenticated users with identical session and packet IDs";
    ASSERT_TRUE(second_decoded);
    EXPECT_TRUE((second_decoded->packet_id == decoded->packet_id &&
          second_decoded->session_owner.size == second_key.size &&
          std::equal(second_key.span().begin(), second_key.span().end(),
                     second_decoded->session_owner.span().begin()) &&
          ingress_replay.Accept(second_decoded->session_owner.span(),
                                authenticated_session, *second_decoded->packet_id))) << "SS2022 external replay namespace truncated the authenticated credential";
    EXPECT_FALSE((ss::DecodeUdpPacket(
              second_packet.data(), second_packet.size(), second_users,
              cipher.type, cipher.key_size, cipher.salt_size, replay_cache, false))) << "SS2022 second user accepted its own repeated packet";

}

void Expect2022Response(const TargetAddress& target, const std::vector<uint8_t>& source,
                        ss::SsCipherType type, size_t key_size) {
    ss::KeyBytes key;
    std::array<uint8_t, 32> key_bytes{};
    for (size_t i = 0; i < key_size; ++i) key_bytes[i] = static_cast<uint8_t>(i + 1);
    ASSERT_TRUE(key.assign(std::span<const uint8_t>(key_bytes).first(key_size)));
    ss::Ss2022UdpSessionState response_encoder;
    ASSERT_TRUE(ss::Init2022UdpSessionState(response_encoder, {type, key_size, key_size}, key));
    response_encoder.client_session_id = {0x00, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde};
    ss::Ss2022UdpSessionState response_decoder;
    response_decoder.cipher_info = response_encoder.cipher_info;
    response_decoder.key = response_encoder.key;
    response_decoder.client_session_id = response_encoder.client_session_id;
    response_decoder.server_session_id = response_encoder.server_session_id;
    const std::span<const uint8_t> payload(source);
    const size_t response_size = ss::Encode2022UdpResponsePacketTo(
        target, payload.data(), payload.size(), response_encoder, nullptr, 0);
    std::vector<uint8_t> response(response_size);
    EXPECT_EQ((ss::Encode2022UdpResponsePacketTo(
              target, payload.data(), payload.size(), response_encoder,
              response.data(), response.size())), (response.size())) << "Shadowsocks 2022 UDP response encoding failed";
    auto response_decoded = ss::Decode2022UdpResponsePacket(
        response.data(), response.size(), response_decoder);
    ASSERT_TRUE(response_decoded);
    EXPECT_TRUE((response_decoded &&
          response_decoded->target.SameEndpoint(target) &&
          Flatten(response_decoded->payload) == source)) << "Shadowsocks 2022 UDP response decoding failed";
    const auto reply_datagram = buf::InspectUdpDatagram(response_decoded->payload);
    EXPECT_TRUE((reply_datagram.Valid() && reply_datagram.target->SameEndpoint(target) &&
          reply_datagram.payload_size == source.size())) << "SS2022 authenticated response lost its UDP message boundary";
    EXPECT_FALSE((ss::Decode2022UdpResponsePacket(
              response.data(), response.size(), response_decoder))) << "Shadowsocks 2022 accepted a replayed response packet";
}

TEST(ShadowsocksUdpDatagram, AssociationInspectionAndPathChangesPreserveReplayHistory) {
    using enum InboundDatagramCheck;
    const udp::endpoint first{net::ip::address_v4::loopback(), 48234};
    const udp::endpoint second{net::ip::address_v4::loopback(), 48235};
    ss::Ss2022UdpAssociation record;
    const auto now = std::chrono::steady_clock::now();
    EXPECT_TRUE((record.Check(10, 0, first, Commit, now))) << "failed to seed protocol association";
    const auto deadline = record.ProtectedUntil();
    EXPECT_TRUE((record.Check(12, 0, second, Inspect, now + std::chrono::seconds(1)) &&
          record.Check(12, 0, second, Inspect, now + std::chrono::seconds(2)) &&
          record.ProtectedUntil() == deadline &&
          record.Check(11, 0, first, Commit, now))) << "inspection committed a packet, changed the path, or extended retention";
    EXPECT_TRUE((record.Check(12, 0, second, Commit) &&
          !record.Check(9, 0, first, Inspect) && !record.Check(9, 0, first, Commit) &&
          record.Check(9, 0, second, Commit) && !record.Check(9, 0, second, Commit))) << "same-Worker path freshness rejected reordering or admitted a stale endpoint";
    EXPECT_TRUE((record.Check(14, 1, first, Commit) &&
          !record.Check(13, 0, second, Inspect) && !record.Check(13, 0, second, Commit) &&
          record.Check(13, 1, first, Commit) && !record.Check(13, 1, first, Commit))) << "cross-Worker path freshness lost replay history or allowed rollback";
    // Reordering on the current path must not lower the path watermark.
    EXPECT_TRUE((record.Check(17, 1, first, Commit) && record.Check(15, 1, first, Commit) &&
          !record.Check(16, 1, second, Inspect) && !record.Check(16, 1, second, Commit) &&
          !record.Check(16, 0, first, Inspect) && !record.Check(16, 0, first, Commit) &&
          record.Check(16, 1, first, Commit) && record.Check(18, 0, second, Commit) &&
          record.Check(20, 2, first, Commit) && !record.Check(19, 0, second, Commit) &&
          record.Check(19, 2, first, Commit))) << "repeated path changes regressed the freshness watermark";
    ss::Ss2022UdpAssociation zero;
    EXPECT_TRUE((zero.Check(0, 0, first, Commit) && !zero.Check(0, 1, second, Commit) &&
          zero.Check(1, 1, second, Commit))) << "zero packet ID bypassed path freshness or replay protection";
}

TEST(ShadowsocksUdpDatagram, ReplayWindowAcceptsReorderingAndRetainsBitsAcrossWords) {
    ss::Ss2022UdpReplayWindow window;
    EXPECT_TRUE((window.Accept(100) && window.Accept(98) && window.Accept(99))) << "Shadowsocks 2022 replay window rejected valid reordering";
    EXPECT_TRUE((!window.Accept(100) && !window.Accept(98))) << "Shadowsocks 2022 replay window accepted duplicate packet IDs";
    EXPECT_TRUE((window.Accept(100 + ss::Ss2022UdpReplayWindow::kWindowBits))) << "Shadowsocks 2022 replay window rejected a new high packet ID";
    EXPECT_FALSE((window.Accept(100))) << "Shadowsocks 2022 replay window accepted an out-of-window packet ID";

    ss::Ss2022UdpReplayWindow cross_word_window;
    EXPECT_TRUE((cross_word_window.Accept(0) && cross_word_window.Accept(65) &&
          !cross_word_window.Accept(0) && cross_word_window.Accept(64) &&
          !cross_word_window.Accept(64))) << "Shadowsocks 2022 replay window lost bits across word boundaries";

}

TEST(ShadowsocksUdpDatagram, ReplayCacheRetentionAndMovePreserveCommittedPackets) {
    ss::Ss2022UdpReplayCache cache;
    const std::array<uint8_t, 8> session_id{1, 2, 3, 4, 5, 6, 7, 8};
    const auto started = std::chrono::steady_clock::time_point{};
    ss::KeyBytes owner;
    const std::array<uint8_t, 16> owner_bytes{1};
    EXPECT_TRUE((owner.assign(owner_bytes))) << "failed to prepare replay test credential";
    EXPECT_TRUE((cache.Accept(owner.span(), session_id, 7, started) &&
          !cache.Accept(owner.span(), session_id, 7, started + std::chrono::seconds(64)) &&
          cache.Accept(owner.span(), session_id, 7, started + std::chrono::seconds(66)))) << "Shadowsocks 2022 replay cache retention is incorrect";

    ss::Ss2022UdpReplayCache previous_cache;
    EXPECT_TRUE((previous_cache.Accept(owner.span(), session_id, 9, started))) << "failed to seed Shadowsocks 2022 replay cache";
    ss::Ss2022UdpReplayCache adopted_cache = std::move(previous_cache);
    EXPECT_FALSE((adopted_cache.Accept(
              owner.span(), session_id, 9, started + std::chrono::seconds(1)))) << "Shadowsocks 2022 replay cache lost state during handler adoption";
}

enum class WriteFault { None, PartialIo, PartialCancel, Allocation, ClosedBeforeStart };

// The transport accepts a prefix before failing. Cancellation uses an actual
// suspended operation, so retrying requires resetting the caller's cancellation.
class FailingWriteStream final : public AsyncStream {
public:
    net::awaitable<size_t> AsyncRead(net::mutable_buffer buffer) override {
        if (!open) co_return 0;
        const size_t count = std::min(buffer.size(), reverse.size() - reverse_offset);
        std::copy_n(reverse.data() + reverse_offset, count, static_cast<uint8_t*>(buffer.data()));
        reverse_offset += count;
        co_return count;
    }
    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override { co_return buf::MultiBuffer{}; }
    net::awaitable<size_t> AsyncWrite(net::const_buffer) override {
        throw std::logic_error("unexpected byte write");
        co_return 0;
    }
    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer mb) override {
        if (!open) throw IoSystemError(io_error::not_connected);
        if (write_closed || fault == WriteFault::ClosedBeforeStart) throw transport::WriteClosed();
        const auto bytes = Flatten(mb);
        const size_t accepted = fault == WriteFault::None ? bytes.size() : std::min(size_t{7}, bytes.size());
        wire.insert(wire.end(), bytes.begin(), bytes.begin() + accepted);
        if (fault == WriteFault::Allocation) throw std::bad_alloc();
        if (fault == WriteFault::PartialIo) throw IoSystemError(io_error::connection_reset);
        if (fault == WriteFault::PartialCancel) {
            const auto executor = co_await net::this_coro::executor;
            net::steady_timer wait(executor);
            wait.expires_at(net::steady_timer::time_point::max());
            net::post(executor, [this] { signal->emit(net::cancellation_type::terminal); });
            IoErrorCode error;
            co_await wait.async_wait(net::redirect_error(net::use_awaitable, error));
            EXPECT_EQ((error), (io_error::operation_aborted)) << "write cancellation did not interrupt a wait";
            throw IoSystemError(error);
        }
    }
    void ShutdownWrite() override { write_closed = true; }
    void Cancel() noexcept override { NotifyCancellation(); }
    void Close() override { Cancel(); open = false; NotifyClosed(); }
    int NativeHandle() const override { return -1; }
    bool IsOpen() const override { return open; }

    WriteFault fault = WriteFault::None;
    net::cancellation_signal* signal = nullptr;
    std::vector<uint8_t> wire;
    const std::array<uint8_t, 3> reverse{0x27, 0x49, 0x68};
    size_t reverse_offset = 0;
    bool write_closed = false;
    bool open = true;
};

net::awaitable<void> WriteTcpPayload(transport::MultiBufferWriter& writer, bool scatter) {
    const std::array<uint8_t, 3> payload{0x31, 0x52, 0x73};
    if (scatter) {
        const std::array<net::const_buffer, 1> buffers{net::buffer(payload)};
        co_await writer.WriteBuffers(buffers);
    } else {
        buf::MultiBuffer mb;
        EXPECT_TRUE((buf::AppendSpanToMultiBuffer(payload, mb))) << "TCP write fixture allocation failed";
        co_await writer.WriteMultiBuffer(std::move(mb));
    }
}


net::awaitable<std::unique_ptr<transport::MultiBufferWriter>> CreateTcpWriter(
    const ss::SsCipherInfo& cipher, const ss::KeyBytes& key, bool response,
    FailingWriteStream& stream) {
    if (response) {
        proxyman::inbound::UserStore::ShadowsocksCredential user;
        EXPECT_TRUE((user.derived_key.assign(key.span()))) << "TCP response credential fixture failed";
        ss::KeyBytes request_salt;
        EXPECT_TRUE((request_salt.assign(key.span()))) << "TCP request salt fixture failed";
        auto result = ss::WriteTCPResponse(user, cipher, request_salt, stream);
        EXPECT_TRUE((bool(result))) << "public TCP response writer creation failed";
        if (!result) throw std::runtime_error("TCP response writer creation failed");
        co_return std::make_unique<ss::SsStreamWriter>(std::move(*result));
    }
    auto result = co_await ss::WriteTCPRequest(
        TargetAddress("1.1.1.1", 443), cipher, key, {}, stream);
    EXPECT_TRUE((bool(result))) << "public TCP request writer creation failed";
    if (!result) throw std::runtime_error("TCP request writer creation failed");
    co_return std::make_unique<ss::SsStreamWriter>(std::move(result->request_writer));
}

void CheckTcpWriterFailure(const ss::SsCipherInfo& cipher, bool response, bool scatter,
                           bool initialized, WriteFault fault) {
    net::io_context io;
    net::cancellation_signal signal;
    FailingWriteStream stream{};
    stream.signal = &signal;
    ss::KeyBytes key;
    std::array<uint8_t, 32> key_bytes{0x17, 0x29, 0x41};
    EXPECT_TRUE((key.assign(std::span<const uint8_t>(key_bytes).first(cipher.key_size)))) << "TCP writer key fixture failed";
    const auto exercise = [&]() -> net::awaitable<void> {
        auto writer = co_await CreateTcpWriter(cipher, key, response, stream);
        if (initialized) co_await WriteTcpPayload(*writer, scatter);
        stream.fault = fault;
        bool failed = false;
        try {
            co_await WriteTcpPayload(*writer, scatter);
        }
        catch (const std::bad_alloc&) {
            failed = fault == WriteFault::Allocation;
        }
        catch (const IoSystemError& error) {
            failed = error.code() == (fault == WriteFault::PartialCancel
                ? io_error::operation_aborted : io_error::connection_reset);
        }
        EXPECT_TRUE((failed)) << "TCP frame write did not preserve its original failure";
        co_await net::this_coro::reset_cancellation_state();
        EXPECT_FALSE(stream.IsOpen()) << "failed encrypted write left its transport reusable";
        const auto wire = stream.wire;
        stream.fault = WriteFault::None;
        for (bool retry_scatter : {false, true}) {
            bool rejected = false;
            try { co_await WriteTcpPayload(*writer, retry_scatter); }
            catch (const IoSystemError&) { rejected = true; }
            EXPECT_TRUE(rejected) << "failed writer emitted another encrypted frame";
        }
        bool rejected = false;
        try { co_await writer->AsyncShutdownWrite(); }
        catch (const IoSystemError&) { rejected = true; }
        EXPECT_TRUE(rejected) << "failed writer half-closed a retired transport";
        EXPECT_EQ(stream.wire, wire);
    };
    auto done = net::co_spawn(io, exercise(),
        net::bind_cancellation_slot(signal.slot(), net::use_future));
    io.run();
    done.get();
}

void CheckTcpCancellationBeforeEncryption(const ss::SsCipherInfo& cipher, bool response) {
    net::io_context io;
    net::cancellation_signal signal;
    FailingWriteStream stream{};
    const auto key = ss::DeriveKey("tcp-writer-admission", cipher.key_size);
    const auto exercise = [&]() -> net::awaitable<void> {
        auto writer = co_await CreateTcpWriter(cipher, key, response, stream);
        co_await WriteTcpPayload(*writer, true);
        const auto wire = stream.wire;
        for (const bool scatter : {false, true}) {
            co_await net::this_coro::throw_if_cancelled(false);
            signal.emit(net::cancellation_type::terminal);
            bool cancelled = false;
            try { co_await WriteTcpPayload(*writer, scatter); }
            catch (const IoSystemError& error) {
                cancelled = error.code() == io_error::operation_aborted;
            }
            co_await net::this_coro::reset_cancellation_state();
            co_await net::this_coro::throw_if_cancelled(true);
            EXPECT_TRUE((cancelled && stream.IsOpen() && stream.wire == wire)) << "cancelled-before-start write progressed or retired a healthy stream";
        }
        co_await WriteTcpPayload(*writer, true);
        std::array<uint8_t, 32> subkey{};
        const auto derive = ss::Is2022Cipher(cipher.type) ? ss::Derive2022Subkey : ss::DeriveSubkey;
        EXPECT_TRUE((derive(key.data(), key.size, stream.wire.data(), cipher.salt_size, subkey.data()))) << "retry decryption subkey derivation failed";
        ss::SsAeadCipher decryptor(cipher.type, subkey.data(), cipher.key_size);
        std::array<uint8_t, 12> nonce{};
        nonce[0] = response ? 2 : 4;
        EXPECT_EQ((stream.wire.size() - wire.size()), (37)) << "retry did not publish one complete encrypted frame";
        std::array<uint8_t, 2> length{};
        const auto* retry = stream.wire.data() + wire.size();
        EXPECT_TRUE((decryptor.Decrypt(nonce.data(), retry, 18, length.data()) &&
              length == std::array<uint8_t, 2>{0, 3})) << "rejected write advanced the next record nonce";
        ++nonce[0];
        std::array<uint8_t, 3> payload{};
        EXPECT_TRUE((decryptor.Decrypt(nonce.data(), retry + 18, 19, payload.data()) &&
              payload == std::array<uint8_t, 3>{0x31, 0x52, 0x73})) << "retry after pre-encryption cancellation changed plaintext";
    };
    auto done = net::co_spawn(io, exercise(),
        net::bind_cancellation_slot(signal.slot(), net::use_future));
    io.run();
    done.get();
}

void CheckTcpFinishedWriter(const ss::SsCipherInfo& cipher, bool response, bool initialized,
                            bool closed_before_start, bool scatter) {
    net::io_context io;
    FailingWriteStream stream{};
    const auto key = ss::DeriveKey("tcp-writer-finished", cipher.key_size);
    const auto exercise = [&]() -> net::awaitable<void> {
        auto writer = co_await CreateTcpWriter(cipher, key, response, stream);
        if (initialized) co_await WriteTcpPayload(*writer, scatter);
        if (closed_before_start) {
            const auto wire = stream.wire;
            stream.fault = WriteFault::ClosedBeforeStart;
            bool closed = false;
            try { co_await WriteTcpPayload(*writer, scatter); }
            catch (const transport::WriteClosed&) { closed = true; }
            EXPECT_TRUE((closed && stream.IsOpen() && stream.wire == wire)) << "definite write-side closure aborted the reverse direction or emitted data";
            stream.fault = WriteFault::None;
        } else {
            co_await writer->AsyncShutdownWrite();
        }
        const auto wire = stream.wire;
        for (const bool retry_scatter : {false, true}) {
            bool closed = false;
            try { co_await WriteTcpPayload(*writer, retry_scatter); }
            catch (const transport::WriteClosed&) { closed = true; }
            EXPECT_TRUE((closed)) << "finished writer did not reject before encryption with WriteClosed";
        }
        co_await writer->AsyncShutdownWrite();
        EXPECT_TRUE((stream.IsOpen() && stream.wire == wire)) << "finished writer altered its transport on reuse";
        std::array<uint8_t, 3> reply{};
        EXPECT_TRUE((co_await stream.AsyncRead(net::buffer(reply)) == reply.size() && reply == stream.reverse)) << "write-side completion discarded reverse-direction data";
    };
    auto done = net::co_spawn(io, exercise(), net::use_future);
    io.run();
    done.get();
}

}  // namespace

class ShadowsocksUdpWire : public testing::TestWithParam<const char*> {};

TEST_P(ShadowsocksUdpWire, LargeDatagramPreservesAuthenticationAndReplayBoundaries) {
    const TargetAddress target("1.1.1.1", 53);
    const std::vector<uint8_t> source(buf::Buffer::kSize + 257, 0x6d);
    const auto packet = MakePayload(source, target);
    const buf::ContiguousBufferView payload(packet);
    const auto cipher = ss::ParseCipherMethod(GetParam());
    ASSERT_TRUE(cipher);
    if (ss::Is2022Cipher(cipher->type))
        Check2022(target, source, payload.Bytes(), cipher->type, cipher->key_size, false);
    else
        CheckClassic(target, source, payload.Bytes(), *cipher);
}

TEST_P(ShadowsocksUdpWire, AuthenticatedEmptyDatagramIsNotRawEmptyWire) {
    const TargetAddress target("1.1.1.1", 53);
    const std::vector<uint8_t> source;
    const auto packet = MakePayload(source, target);
    const buf::ContiguousBufferView payload(packet);
    const auto cipher = ss::ParseCipherMethod(GetParam());
    ASSERT_TRUE(cipher);
    if (ss::Is2022Cipher(cipher->type))
        Check2022(target, source, payload.Bytes(), cipher->type, cipher->key_size, false);
    else
        CheckClassic(target, source, payload.Bytes(), *cipher);
}

TEST_P(ShadowsocksUdpWire, ShortDomainsPreserveEmptyAndSingleByteDatagrams) {
    const auto cipher = ss::ParseCipherMethod(GetParam());
    ASSERT_TRUE(cipher);
    for (std::string_view host : {"a", "ab"}) {
        SCOPED_TRACE(host);
        const TargetAddress target(host, 54321);
        for (size_t length : {size_t{0}, size_t{1}}) {
            SCOPED_TRACE(length);
            const std::vector<uint8_t> source(length, 0x7b);
            const auto packet = MakePayload(source, target);
            const buf::ContiguousBufferView payload(packet);
            if (ss::Is2022Cipher(cipher->type))
                Check2022(target, source, payload.Bytes(), cipher->type, cipher->key_size, false);
            else
                CheckClassic(target, source, payload.Bytes(), *cipher);
        }
    }
}

INSTANTIATE_TEST_SUITE_P(CipherMethods, ShadowsocksUdpWire, testing::Values(
    "aes-128-gcm", "aes-256-gcm", "chacha20-poly1305", "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"));

class Shadowsocks2022UdpWire : public testing::TestWithParam<const char*> {};

TEST_P(Shadowsocks2022UdpWire, IdentityAuthenticationScopesReplayToFullUserCredential) {
    const auto cipher = ss::ParseCipherMethod(GetParam());
    ASSERT_TRUE(cipher);
    for (const size_t size : {size_t{0}, size_t{1}, buf::Buffer::kSize + size_t{257}}) {
        SCOPED_TRACE(size);
        for (std::string_view host : {"1.1.1.1", "a", "ab"}) {
            SCOPED_TRACE(host);
            const TargetAddress target(host, 54321);
            const std::vector<uint8_t> source(size, 0x7b);
            const auto packet = MakePayload(source, target);
            const buf::ContiguousBufferView payload(packet);
            Check2022(target, source, payload.Bytes(), cipher->type, cipher->key_size, true);
        }
    }
}

INSTANTIATE_TEST_SUITE_P(IdentityMethods, Shadowsocks2022UdpWire,
    testing::Values("2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm"));

class Shadowsocks2022UdpReply : public testing::TestWithParam<const char*> {};

TEST_P(Shadowsocks2022UdpReply, ResponsePreservesPayloadBoundaryAndRejectsReplay) {
    const auto cipher = ss::ParseCipherMethod(GetParam());
    ASSERT_TRUE(cipher);
    for (const size_t size : {size_t{0}, size_t{1}, buf::Buffer::kSize + size_t{257}}) {
        SCOPED_TRACE(size);
        for (std::string_view host : {"1.1.1.1", "a", "ab"}) {
            SCOPED_TRACE(host);
            Expect2022Response(TargetAddress(host, 54321),
                std::vector<uint8_t>(size, 0x7b), cipher->type, cipher->key_size);
        }
    }
}

INSTANTIATE_TEST_SUITE_P(ResponseMethods, Shadowsocks2022UdpReply,
    testing::Values("2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
                    "2022-blake3-chacha20-poly1305"));

constexpr std::array writer_methods{
    "aes-128-gcm", "aes-256-gcm", "chacha20-poly1305",
    "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305"};

class ShadowsocksTcpWriteFailure : public testing::TestWithParam<
    std::tuple<const char*, bool, bool, bool, WriteFault>> {};

TEST_P(ShadowsocksTcpWriteFailure, FailedFrameRetiresWriterAndTransport) {
    const auto [method, response, scatter, initialized, fault] = GetParam();
    const auto cipher = ss::ParseCipherMethod(method);
    ASSERT_TRUE(cipher);
    CheckTcpWriterFailure(*cipher, response, scatter, initialized, fault);
}

INSTANTIATE_TEST_SUITE_P(WritePaths, ShadowsocksTcpWriteFailure, testing::Combine(
    testing::ValuesIn(writer_methods), testing::Bool(), testing::Bool(), testing::Bool(),
    testing::Values(WriteFault::PartialIo, WriteFault::PartialCancel, WriteFault::Allocation)));

class ShadowsocksTcpAdmission : public testing::TestWithParam<std::tuple<const char*, bool>> {};

TEST_P(ShadowsocksTcpAdmission, PreEncryptionCancellationPreservesNextRecordNonce) {
    const auto [method, response] = GetParam();
    const auto cipher = ss::ParseCipherMethod(method);
    ASSERT_TRUE(cipher);
    CheckTcpCancellationBeforeEncryption(*cipher, response);
}

INSTANTIATE_TEST_SUITE_P(Directions, ShadowsocksTcpAdmission, testing::Combine(
    testing::ValuesIn(writer_methods), testing::Bool()));

class ShadowsocksTcpWriteEnd : public testing::TestWithParam<
    std::tuple<const char*, bool, bool, bool, bool>> {};

TEST_P(ShadowsocksTcpWriteEnd, FinishedWriterPreservesReverseRead) {
    const auto [method, response, initialized, closed_before_start, scatter] = GetParam();
    const auto cipher = ss::ParseCipherMethod(method);
    ASSERT_TRUE(cipher);
    CheckTcpFinishedWriter(*cipher, response, initialized, closed_before_start, scatter);
}

INSTANTIATE_TEST_SUITE_P(WritePaths, ShadowsocksTcpWriteEnd, testing::Combine(
    testing::ValuesIn(writer_methods), testing::Bool(), testing::Bool(), testing::Bool(), testing::Bool()));
