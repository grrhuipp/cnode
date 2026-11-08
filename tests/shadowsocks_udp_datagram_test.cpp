#include <stdexcept>
#include <gtest/gtest.h>

#include "ss_udp.hpp"
#include "shadowsocks_crypto.hpp"
#include "client.hpp"
#include "server.hpp"
#include <asio/bind_cancellation_slot.hpp>
#include <asio/cancellation_signal.hpp>
#include <asio/co_spawn.hpp>
#include <asio/post.hpp>
#include <asio/redirect_error.hpp>
#include <asio/steady_timer.hpp>
#include <asio/use_future.hpp>
#include "common/buf/contiguous_buffer_view.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <string_view>
#include <vector>

namespace {


[[noreturn]] void Fail(std::string_view message) {
    std::cerr << message << '\n';
    ADD_FAILURE() << "contract assertion failed; see diagnostic above"; throw std::runtime_error("contract assertion failed");
}

void Check(bool condition, std::string_view message) {
    if (!condition) {
        Fail(message);
    }
}

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
    Check(buf::AppendSpanToMultiBuffer(source, payload),
          "failed to allocate Shadowsocks UDP test payload");
    Check(buf::SetUdpTarget(payload, target),
          "failed to mark Shadowsocks UDP test datagram");
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
    Check(ss::EncodeUdpPacketTo(
              target, payload.data(), payload.size(), key.span(),
              cipher.type, cipher.key_size, cipher.salt_size,
              encoded.data(), encoded.size()) == encoded.size(),
          "classic Shadowsocks UDP encoding failed");

    auto decoded = ss::DecodeUdpPacketWithKey(
        encoded.data(), encoded.size(), key.span(),
        cipher.type, cipher.key_size, cipher.salt_size);
    Check(decoded && decoded->target.SameEndpoint(target) &&
          Flatten(decoded->payload) == source,
          "classic Shadowsocks split one MultiBuffer datagram");
    Check(!decoded->session_id, "classic UDP unexpectedly supplied a protocol session ID");
    Check(!decoded->packet_id, "classic UDP unexpectedly supplied an authenticated packet ID");
    const auto reply_datagram = buf::InspectUdpDatagram(decoded->payload);
    Check(reply_datagram.Valid() && reply_datagram.target->SameEndpoint(target) &&
          reply_datagram.payload_size == source.size(),
          "classic Shadowsocks reply lost its UDP message boundary");

    auto user_list = std::make_shared<
        proxyman::inbound::UserStore::ShadowsocksUserList>();
    proxyman::inbound::UserStore::ShadowsocksCredential user;
    Check(user.derived_key.assign(key.span()), "failed to prepare classic UDP user");
    user_list->push_back(std::move(user));
    ss::Ss2022UdpReplayCache replay_cache;
    for (bool deferred_replay : {false, true}) {
        auto inbound = ss::DecodeUdpPacket(
            encoded.data(), encoded.size(), {user_list},
            cipher.type, cipher.key_size, cipher.salt_size, replay_cache, deferred_replay);
        Check(inbound && !inbound->session_id && !inbound->packet_id &&
              inbound->target.SameEndpoint(target) && Flatten(inbound->payload) == source &&
              replay_cache.Size() == 0,
              "deferred replay changed classic UDP decoding");
        const auto request_datagram = buf::InspectUdpDatagram(inbound->payload);
        Check(request_datagram.Valid() && request_datagram.target->SameEndpoint(target) &&
              request_datagram.payload_size == source.size(),
              "classic authenticated request lost its UDP message boundary");
    }

    Check(!ss::DecodeUdpPacket(nullptr, 0, {user_list}, cipher.type,
                              cipher.key_size, cipher.salt_size, replay_cache) &&
          !ss::DecodeUdpPacketWithKey(nullptr, 0, key.span(), cipher.type,
                                     cipher.key_size, cipher.salt_size),
          "raw empty Shadowsocks wire bypassed authentication");
    // Cross-check the one-shot AEAD API against the existing streaming EVP
    // implementation, rather than only round-tripping through the new path.
    std::array<uint8_t, 32> subkey{};
    std::array<uint8_t, 12> nonce{};
    Check(ss::DeriveSubkey(key.data(), key.size, encoded.data(), cipher.salt_size,
                          subkey.data()), "reference subkey derivation failed");
    ss::SsAeadCipher reference(cipher.type, subkey.data(), cipher.key_size,
                               proxy::AeadDirection::Decrypt);
    const auto body = std::span<const uint8_t>(encoded).subspan(cipher.salt_size);
    std::vector<uint8_t> plaintext(body.size() - ss::SsAeadCipher::kTagSize);
    Check(reference.Decrypt(nonce.data(), body.data(), body.size(), plaintext.data()),
          "EVP could not decrypt one-shot AEAD ciphertext");
    Check(std::equal(source.begin(), source.end(), plaintext.end() - source.size()),
          "reference AEAD plaintext mismatch");
    std::vector<uint8_t> reference_ciphertext(body.size());
    ss::SsAeadCipher encoder(cipher.type, subkey.data(), cipher.key_size,
                             proxy::AeadDirection::Encrypt);
    Check(encoder.Encrypt(nonce.data(), plaintext.data(), plaintext.size(), reference_ciphertext.data()) &&
          std::equal(body.begin(), body.end(), reference_ciphertext.begin()),
          "AEAD ciphertext/tag differ from streaming EVP");
    encoded.back() ^= 1;
    Check(!ss::DecodeUdpPacketWithKey(encoded.data(), encoded.size(), key.span(),
                                    cipher.type, cipher.key_size, cipher.salt_size),
          "datagram AEAD accepted a modified tag");
}

void Check2022(const TargetAddress& target,
               const std::vector<uint8_t>& source,
               std::span<const uint8_t> payload,
               ss::SsCipherType cipher_type,
               size_t key_size,
               bool identity = false) {
    const ss::SsCipherInfo cipher{cipher_type, key_size, key_size};
    ss::KeyBytes key;
    std::array<uint8_t, 32> key_bytes{};
    for (size_t i = 0; i < key_size; ++i) {
        key_bytes[i] = static_cast<uint8_t>(i + 1);
    }
    Check(key.assign(std::span<const uint8_t>(key_bytes).first(key_size)),
          "failed to initialize Shadowsocks 2022 key");

    std::array<ss::KeyBytes, 2> chain{};
    std::span<const ss::KeyBytes> psk_chain;
    if (identity) {
        auto identity_bytes = key_bytes;
        for (auto& byte : identity_bytes) byte ^= 0xa5;
        Check(chain[0].assign(std::span<const uint8_t>(identity_bytes).first(key_size)),
              "failed to initialize identity key");
        chain[1] = key;
        psk_chain = chain;
    }
    ss::Ss2022UdpSessionState encoder;
    Check(ss::Init2022UdpSessionState(encoder, cipher, key),
          "failed to initialize Shadowsocks 2022 UDP state");
    encoder.client_session_id = {0x00, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde};
    const size_t encoded_size = ss::Encode2022UdpRequestPacketTo(
        target, payload.data(), payload.size(), encoder, psk_chain, nullptr, 0);
    Check(encoder.next_packet_id == 0,
          "Shadowsocks 2022 size calculation advanced packet state");
    std::vector<uint8_t> encoded(encoded_size);
    Check(ss::Encode2022UdpRequestPacketTo(
              target, payload.data(), payload.size(), encoder, psk_chain,
              encoded.data(), encoded.size()) == encoded.size(),
          "Shadowsocks 2022 UDP encoding failed");
    Check(encoder.next_packet_id == 1,
          "Shadowsocks 2022 request did not advance packet state once");

    auto user_list = std::make_shared<
        proxyman::inbound::UserStore::ShadowsocksUserList>();
    proxyman::inbound::UserStore::ShadowsocksCredential user;
    Check(user.derived_key.assign(key.span()),
          "failed to initialize Shadowsocks 2022 decode user");
    if (identity) {
        Check(user.identity_key.assign(chain[0].span()) &&
              ss::Hash2022Psk(key.span(), user.psk_hash),
              "failed to prepare identity credential");
    }
    user.key_size = cipher.key_size;
    user.salt_size = cipher.salt_size;
    if (identity) {
        auto decoy = user;
        decoy.derived_key.bytes[0] ^= 0x5a;
        Check(ss::Hash2022Psk(decoy.derived_key.span(), decoy.psk_hash),
              "failed to prepare decoy credential");
        auto other_identity = decoy;
        other_identity.identity_key.bytes[0] ^= 0x33;
        user_list->push_back(std::move(other_identity));
        user_list->push_back(std::move(decoy));
    }
    user_list->push_back(std::move(user));
    const proxyman::inbound::UserStore::ShadowsocksUsersView users{user_list};
    if (identity) {
        auto bad_users = std::make_shared<proxyman::inbound::UserStore::ShadowsocksUserList>(*user_list);
        bad_users->back().psk_hash[0] ^= 1;
        ss::Ss2022UdpReplayCache bad_cache;
        Check(!ss::DecodeUdpPacket(encoded.data(), encoded.size(), {bad_users},
                                  cipher.type, cipher.key_size, cipher.salt_size, bad_cache),
              "identity authentication ignored prepared PSK hash");
        Check(!ss::DecodeUdpPacket(encoded.data(), encoded.size(), {bad_users},
                                  cipher.type, cipher.key_size, cipher.salt_size, bad_cache, true) &&
              bad_cache.Size() == 0,
              "deferred identity authentication accepted an invalid PSK hash or mutated replay");
    }
    std::vector<uint8_t> corrupted = encoded;
    corrupted.back() ^= 0x01;
    ss::Ss2022UdpReplayCache validation_cache;
    Check(!ss::DecodeUdpPacket(
              corrupted.data(), corrupted.size(), users,
              cipher.type, cipher.key_size, cipher.salt_size,
              validation_cache),
          "invalid Shadowsocks 2022 request unexpectedly decoded");
    Check(validation_cache.Size() == 0,
          "invalid Shadowsocks 2022 authentication created replay state");
    Check(!ss::DecodeUdpPacket(
              corrupted.data(), corrupted.size(), users,
              cipher.type, cipher.key_size, cipher.salt_size, validation_cache, true) &&
          validation_cache.Size() == 0,
          "deferred invalid authentication accepted ciphertext or mutated replay");
    Check(!ss::DecodeUdpPacket(nullptr, 0, users, cipher.type, cipher.key_size,
                              cipher.salt_size, validation_cache) &&
          validation_cache.Size() == 0,
          "raw empty SS2022 wire bypassed authentication or created replay state");
    Check(ss::DecodeUdpPacket(
              encoded.data(), encoded.size(), users,
              cipher.type, cipher.key_size, cipher.salt_size,
              validation_cache).has_value(),
          "invalid Shadowsocks 2022 request poisoned the replay window");

    ss::Ss2022UdpReplayCache replay_cache;
    for (size_t attempt = 0; attempt < 2; ++attempt) {
        auto authenticated = ss::DecodeUdpPacket(
            encoded.data(), encoded.size(), users,
            cipher.type, cipher.key_size, cipher.salt_size, replay_cache, true);
        Check(authenticated && authenticated->session_id == 0x00123456789abcdeULL &&
              authenticated->packet_id == 0 &&
              authenticated->session_owner.size == key.size &&
              std::equal(key.span().begin(), key.span().end(),
                         authenticated->session_owner.span().begin()) &&
              authenticated->target.SameEndpoint(target) &&
              Flatten(authenticated->payload) == source && replay_cache.Size() == 0,
              "SS2022 authentication lost metadata or committed replay");
    }
    auto decoded = ss::DecodeUdpPacket(
        encoded.data(), encoded.size(), users,
        cipher.type, cipher.key_size, cipher.salt_size, replay_cache);
    Check(decoded && decoded->target.SameEndpoint(target) &&
          Flatten(decoded->payload) == source,
          "Shadowsocks 2022 split one MultiBuffer datagram");
    const auto request_datagram = buf::InspectUdpDatagram(decoded->payload);
    Check(request_datagram.Valid() && request_datagram.target->SameEndpoint(target) &&
          request_datagram.payload_size == source.size(),
          "SS2022 authenticated request lost its UDP message boundary");
    Check(decoded->session_id == 0x00123456789abcdeULL,
          "Shadowsocks 2022 session ID lost byte order or leading zeros");
    Check(decoded->packet_id == 0 && decoded->session_owner.size == key.size &&
          std::equal(key.span().begin(), key.span().end(), decoded->session_owner.span().begin()),
          "SS2022 decode lost authenticated packet ID or full credential");
    Check(!ss::DecodeUdpPacket(
              encoded.data(), encoded.size(), users,
              cipher.type, cipher.key_size, cipher.salt_size, replay_cache),
          "Shadowsocks 2022 accepted a replayed request packet");
    auto authenticated_replay = ss::DecodeUdpPacket(
        encoded.data(), encoded.size(), users,
        cipher.type, cipher.key_size, cipher.salt_size, replay_cache, true);
    Check(authenticated_replay && replay_cache.Size() == 1,
          "deferred authentication consulted already committed replay state");
    std::array<uint8_t, 8> authenticated_session{};
    for (size_t i = 0; i < authenticated_session.size(); ++i) {
        authenticated_session[i] = static_cast<uint8_t>(
            *authenticated_replay->session_id >> ((authenticated_session.size() - 1 - i) * 8));
    }
    ss::Ss2022UdpReplayCache ingress_replay;
    Check(ingress_replay.Accept(authenticated_replay->session_owner.span(),
                               authenticated_session, *authenticated_replay->packet_id) &&
          !ingress_replay.Accept(authenticated_replay->session_owner.span(),
                                authenticated_session, *authenticated_replay->packet_id),
          "authenticated metadata did not support a unique external replay commit");

    // A forged high packet ID must not advance an already initialized window.
    constexpr uint64_t kHighPacketId = 0x0102030405060708ULL;
    encoder.next_packet_id = kHighPacketId;
    std::vector<uint8_t> high_packet(encoded_size);
    Check(ss::Encode2022UdpRequestPacketTo(
              target, payload.data(), payload.size(), encoder, psk_chain,
              high_packet.data(), high_packet.size()) == high_packet.size(),
          "failed to encode high packet ID");
    high_packet.back() ^= 1;
    for (bool deferred_replay : {false, true}) {
        Check(!ss::DecodeUdpPacket(
                  high_packet.data(), high_packet.size(), users,
                  cipher.type, cipher.key_size, cipher.salt_size, replay_cache, deferred_replay) &&
              replay_cache.Size() == 1,
              "invalid authentication changed an existing replay namespace");
    }
    encoder.next_packet_id = 1;
    std::vector<uint8_t> next_packet(encoded_size);
    Check(ss::Encode2022UdpRequestPacketTo(
              target, payload.data(), payload.size(), encoder, psk_chain,
              next_packet.data(), next_packet.size()) == next_packet.size(),
          "failed to encode next packet ID");
    auto next_decoded = ss::DecodeUdpPacket(
        next_packet.data(), next_packet.size(), users,
        cipher.type, cipher.key_size, cipher.salt_size, replay_cache);
    Check(next_decoded && next_decoded->packet_id == 1,
          "invalid authentication advanced the replay window");
    high_packet.back() ^= 1;
    auto high_authenticated = ss::DecodeUdpPacket(
        high_packet.data(), high_packet.size(), users,
        cipher.type, cipher.key_size, cipher.salt_size, replay_cache, true);
    Check(high_authenticated && high_authenticated->packet_id == kHighPacketId,
          "SS2022 authenticated packet ID lost width or byte order");
    Check(!ss::DecodeUdpPacket(
              next_packet.data(), next_packet.size(), users,
              cipher.type, cipher.key_size, cipher.salt_size, replay_cache),
          "deferred authentication cleared existing replay history");
    // Distinct authenticated users may independently choose identical session
    // and packet IDs. Authentication must scope the replay window too.
    ss::KeyBytes second_key = key;
    second_key.bytes[second_key.size - 1] ^= 0x5a;
    auto second_user = user_list->back();
    Check(second_user.derived_key.assign(second_key.span()), "failed to prepare second user's key");
    if (identity)
        Check(ss::Hash2022Psk(second_key.span(), second_user.psk_hash),
              "failed to prepare second identity credential");
    user_list->push_back(std::move(second_user));
    ss::Ss2022UdpSessionState second_encoder;
    Check(ss::Init2022UdpSessionState(second_encoder, cipher, second_key),
          "failed to prepare second user's UDP session");
    second_encoder.client_session_id = encoder.client_session_id;
    if (identity) chain[1] = second_key;
    const size_t second_size = ss::Encode2022UdpRequestPacketTo(
        target, payload.data(), payload.size(), second_encoder, psk_chain, nullptr, 0);
    std::vector<uint8_t> second_packet(second_size);
    Check(second_size != 0 && ss::Encode2022UdpRequestPacketTo(
              target, payload.data(), payload.size(), second_encoder, psk_chain,
              second_packet.data(), second_packet.size()) == second_size,
          "failed to encode second user's UDP packet");
    auto second_decoded = ss::DecodeUdpPacket(
        second_packet.data(), second_packet.size(), users,
        cipher.type, cipher.key_size, cipher.salt_size, replay_cache);
    Check(second_decoded && second_decoded->session_id == decoded->session_id &&
          second_decoded->user_index != decoded->user_index &&
          Flatten(second_decoded->payload) == source,
          "SS2022 replay state crossed authenticated users with identical session and packet IDs");
    Check(second_decoded->packet_id == decoded->packet_id &&
          second_decoded->session_owner.size == second_key.size &&
          std::equal(second_key.span().begin(), second_key.span().end(),
                     second_decoded->session_owner.span().begin()) &&
          ingress_replay.Accept(second_decoded->session_owner.span(),
                                authenticated_session, *second_decoded->packet_id),
          "SS2022 external replay namespace truncated the authenticated credential");
    Check(!ss::DecodeUdpPacket(
              second_packet.data(), second_packet.size(), users,
              cipher.type, cipher.key_size, cipher.salt_size, replay_cache),
          "SS2022 second user accepted its own repeated packet");

    auto make_response_state = [&]() {
        ss::Ss2022UdpSessionState state;
        state.cipher_info = encoder.cipher_info;
        state.key = encoder.key;
        state.client_session_id = encoder.client_session_id;
        state.server_session_id = encoder.server_session_id;
        return state;
    };
    ss::Ss2022UdpSessionState response_encoder = make_response_state();
    ss::Ss2022UdpSessionState response_decoder = make_response_state();
    const size_t response_size = ss::Encode2022UdpResponsePacketTo(
        target, payload.data(), payload.size(), response_encoder, nullptr, 0);
    std::vector<uint8_t> response(response_size);
    Check(ss::Encode2022UdpResponsePacketTo(
              target, payload.data(), payload.size(), response_encoder,
              response.data(), response.size()) == response.size(),
          "Shadowsocks 2022 UDP response encoding failed");
    auto response_decoded = ss::Decode2022UdpResponsePacket(
        response.data(), response.size(), response_decoder);
    Check(response_decoded &&
          response_decoded->target.SameEndpoint(target) &&
          Flatten(response_decoded->payload) == source,
          "Shadowsocks 2022 UDP response decoding failed");
    const auto reply_datagram = buf::InspectUdpDatagram(response_decoded->payload);
    Check(reply_datagram.Valid() && reply_datagram.target->SameEndpoint(target) &&
          reply_datagram.payload_size == source.size(),
          "SS2022 authenticated response lost its UDP message boundary");
    Check(!ss::Decode2022UdpResponsePacket(
              response.data(), response.size(), response_decoder),
          "Shadowsocks 2022 accepted a replayed response packet");
}

void Check2022AssociationPaths() {
    using enum InboundDatagramCheck;
    const udp::endpoint first{net::ip::address_v4::loopback(), 48234};
    const udp::endpoint second{net::ip::address_v4::loopback(), 48235};
    ss::Ss2022UdpAssociation record;
    const auto now = std::chrono::steady_clock::now();
    Check(record.Check(10, 0, first, Commit, now), "failed to seed protocol association");
    const auto deadline = record.ProtectedUntil();
    Check(record.Check(12, 0, second, Inspect, now + std::chrono::seconds(1)) &&
          record.Check(12, 0, second, Inspect, now + std::chrono::seconds(2)) &&
          record.ProtectedUntil() == deadline &&
          record.Check(11, 0, first, Commit, now),
          "inspection committed a packet, changed the path, or extended retention");
    Check(record.Check(12, 0, second, Commit) &&
          !record.Check(9, 0, first, Inspect) && !record.Check(9, 0, first, Commit) &&
          record.Check(9, 0, second, Commit) && !record.Check(9, 0, second, Commit),
          "same-Worker path freshness rejected reordering or admitted a stale endpoint");
    Check(record.Check(14, 1, first, Commit) &&
          !record.Check(13, 0, second, Inspect) && !record.Check(13, 0, second, Commit) &&
          record.Check(13, 1, first, Commit) && !record.Check(13, 1, first, Commit),
          "cross-Worker path freshness lost replay history or allowed rollback");
    // Reordering on the current path must not lower the path watermark.
    Check(record.Check(17, 1, first, Commit) && record.Check(15, 1, first, Commit) &&
          !record.Check(16, 1, second, Inspect) && !record.Check(16, 1, second, Commit) &&
          !record.Check(16, 0, first, Inspect) && !record.Check(16, 0, first, Commit) &&
          record.Check(16, 1, first, Commit) && record.Check(18, 0, second, Commit) &&
          record.Check(20, 2, first, Commit) && !record.Check(19, 0, second, Commit) &&
          record.Check(19, 2, first, Commit),
          "repeated path changes regressed the freshness watermark");
    ss::Ss2022UdpAssociation zero;
    Check(zero.Check(0, 0, first, Commit) && !zero.Check(0, 1, second, Commit) &&
          zero.Check(1, 1, second, Commit),
          "zero packet ID bypassed path freshness or replay protection");
}

void Check2022ReplayWindow() {
    ss::Ss2022UdpReplayWindow window;
    Check(window.Accept(100) && window.Accept(98) && window.Accept(99),
          "Shadowsocks 2022 replay window rejected valid reordering");
    Check(!window.Accept(100) && !window.Accept(98),
          "Shadowsocks 2022 replay window accepted duplicate packet IDs");
    Check(window.Accept(100 + ss::Ss2022UdpReplayWindow::kWindowBits),
          "Shadowsocks 2022 replay window rejected a new high packet ID");
    Check(!window.Accept(100),
          "Shadowsocks 2022 replay window accepted an out-of-window packet ID");

    ss::Ss2022UdpReplayWindow cross_word_window;
    Check(cross_word_window.Accept(0) && cross_word_window.Accept(65) &&
          !cross_word_window.Accept(0) && cross_word_window.Accept(64) &&
          !cross_word_window.Accept(64),
          "Shadowsocks 2022 replay window lost bits across word boundaries");

    ss::Ss2022UdpReplayCache cache;
    const std::array<uint8_t, 8> session_id{1, 2, 3, 4, 5, 6, 7, 8};
    const auto started = std::chrono::steady_clock::time_point{};
    ss::KeyBytes owner;
    const std::array<uint8_t, 16> owner_bytes{1};
    Check(owner.assign(owner_bytes), "failed to prepare replay test credential");
    Check(cache.Accept(owner.span(), session_id, 7, started) &&
          !cache.Accept(owner.span(), session_id, 7, started + std::chrono::seconds(64)) &&
          cache.Accept(owner.span(), session_id, 7, started + std::chrono::seconds(66)),
          "Shadowsocks 2022 replay cache retention is incorrect");

    ss::Ss2022UdpReplayCache previous_cache;
    Check(previous_cache.Accept(owner.span(), session_id, 9, started),
          "failed to seed Shadowsocks 2022 replay cache");
    ss::Ss2022UdpReplayCache adopted_cache = std::move(previous_cache);
    Check(!adopted_cache.Accept(
              owner.span(), session_id, 9, started + std::chrono::seconds(1)),
          "Shadowsocks 2022 replay cache lost state during handler adoption");
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
            Check(error == io_error::operation_aborted, "write cancellation did not interrupt a wait");
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
        Check(buf::AppendSpanToMultiBuffer(payload, mb), "TCP write fixture allocation failed");
        co_await writer.WriteMultiBuffer(std::move(mb));
    }
}


net::awaitable<std::unique_ptr<transport::MultiBufferWriter>> CreateTcpWriter(
    const ss::SsCipherInfo& cipher, const ss::KeyBytes& key, bool response,
    FailingWriteStream& stream) {
    if (response) {
        proxyman::inbound::UserStore::ShadowsocksCredential user;
        Check(user.derived_key.assign(key.span()), "TCP response credential fixture failed");
        user.key_size = cipher.key_size;
        user.salt_size = cipher.salt_size;
        ss::KeyBytes request_salt;
        Check(request_salt.assign(key.span()), "TCP request salt fixture failed");
        auto result = ss::WriteTCPResponse(user, cipher, request_salt, stream);
        Check(bool(result), "public TCP response writer creation failed");
        co_return std::move(*result);
    }
    auto result = co_await ss::WriteTCPRequest(
        TargetAddress("1.1.1.1", 443), cipher, key, {}, stream);
    Check(bool(result), "public TCP request writer creation failed");
    co_return std::move(result->request_writer);
}

void CheckTcpWriterFailure(const ss::SsCipherInfo& cipher, bool response, bool scatter,
                           bool initialized, WriteFault fault) {
    net::io_context io;
    net::cancellation_signal signal;
    FailingWriteStream stream;
    stream.signal = &signal;
    ss::KeyBytes key;
    std::array<uint8_t, 32> key_bytes{0x17, 0x29, 0x41};
    Check(key.assign(std::span<const uint8_t>(key_bytes).first(cipher.key_size)),
          "TCP writer key fixture failed");
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
        Check(failed, "TCP frame write did not preserve its original failure");
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
    FailingWriteStream stream;
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
            Check(cancelled && stream.IsOpen() && stream.wire == wire,
                  "cancelled-before-start write progressed or retired a healthy stream");
        }
        co_await WriteTcpPayload(*writer, true);
        std::array<uint8_t, 32> subkey{};
        const auto derive = ss::Is2022Cipher(cipher.type) ? ss::Derive2022Subkey : ss::DeriveSubkey;
        Check(derive(key.data(), key.size, stream.wire.data(), cipher.salt_size, subkey.data()),
              "retry decryption subkey derivation failed");
        ss::SsAeadCipher decryptor(cipher.type, subkey.data(), cipher.key_size, proxy::AeadDirection::Decrypt);
        std::array<uint8_t, 12> nonce{};
        nonce[0] = response ? 2 : 4;
        Check(stream.wire.size() - wire.size() == 37, "retry did not publish one complete encrypted frame");
        std::array<uint8_t, 2> length{};
        const auto* retry = stream.wire.data() + wire.size();
        Check(decryptor.Decrypt(nonce.data(), retry, 18, length.data()) &&
              length == std::array<uint8_t, 2>{0, 3}, "rejected write advanced the next record nonce");
        ++nonce[0];
        std::array<uint8_t, 3> payload{};
        Check(decryptor.Decrypt(nonce.data(), retry + 18, 19, payload.data()) &&
              payload == std::array<uint8_t, 3>{0x31, 0x52, 0x73},
              "retry after pre-encryption cancellation changed plaintext");
    };
    auto done = net::co_spawn(io, exercise(),
        net::bind_cancellation_slot(signal.slot(), net::use_future));
    io.run();
    done.get();
}

void CheckTcpFinishedWriter(const ss::SsCipherInfo& cipher, bool response, bool initialized,
                            bool closed_before_start, bool scatter) {
    net::io_context io;
    FailingWriteStream stream;
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
            Check(closed && stream.IsOpen() && stream.wire == wire,
                  "definite write-side closure aborted the reverse direction or emitted data");
            stream.fault = WriteFault::None;
        } else {
            co_await writer->AsyncShutdownWrite();
        }
        const auto wire = stream.wire;
        for (const bool retry_scatter : {false, true}) {
            bool closed = false;
            try { co_await WriteTcpPayload(*writer, retry_scatter); }
            catch (const transport::WriteClosed&) { closed = true; }
            Check(closed, "finished writer did not reject before encryption with WriteClosed");
        }
        co_await writer->AsyncShutdownWrite();
        Check(stream.IsOpen() && stream.wire == wire, "finished writer altered its transport on reuse");
        std::array<uint8_t, 3> reply{};
        Check(co_await stream.AsyncRead(net::buffer(reply)) == reply.size() && reply == stream.reverse,
              "write-side completion discarded reverse-direction data");
    };
    auto done = net::co_spawn(io, exercise(), net::use_future);
    io.run();
    done.get();
}

}  // namespace

TEST(ShadowsocksUdpDatagram, Contract) {
    const TargetAddress target("1.1.1.1", 53);
    const std::vector<uint8_t> source(buf::Buffer::kSize + 257, 0x6d);
    const buf::MultiBuffer fragmented = MakePayload(source, target);
    const buf::ContiguousBufferView payload(fragmented);
    Check(payload.Bytes().size() == source.size() &&
          std::equal(payload.Bytes().begin(), payload.Bytes().end(), source.begin()),
          "Shadowsocks UDP payload coalescing mismatch");

    for (std::string_view method : {"aes-128-gcm", "aes-256-gcm", "chacha20-poly1305"}) {
        const auto cipher = ss::ParseCipherMethod(method);
        Check(cipher.has_value(), "test cipher unavailable");
        CheckClassic(target, source, payload.Bytes(), *cipher);
    }
    Check2022(target, source, payload.Bytes(), ss::SsCipherType::AES_256_GCM_2022, 32);
    Check2022(target, source, payload.Bytes(), ss::SsCipherType::AES_128_GCM_2022, 16);
    Check2022(target, source, payload.Bytes(), ss::SsCipherType::CHACHA20_POLY1305_2022, 32);
    Check2022(target, source, payload.Bytes(), ss::SsCipherType::AES_128_GCM_2022, 16, true);
    Check2022(target, source, payload.Bytes(), ss::SsCipherType::AES_256_GCM_2022, 32, true);
    Check2022ReplayWindow();
    Check2022AssociationPaths();
}

TEST(ShadowsocksUdpDatagram, AuthenticatedEmptyDatagrams) {
    const TargetAddress target("1.1.1.1", 53);
    const std::vector<uint8_t> source;
    const auto packet = MakePayload(source, target);
    const buf::ContiguousBufferView payload(packet);
    for (std::string_view method : {"aes-128-gcm", "aes-256-gcm", "chacha20-poly1305"}) {
        const auto cipher = ss::ParseCipherMethod(method);
        Check(cipher.has_value(), "test cipher unavailable");
        CheckClassic(target, source, payload.Bytes(), *cipher);
    }
    Check2022(target, source, payload.Bytes(), ss::SsCipherType::AES_128_GCM_2022, 16);
    Check2022(target, source, payload.Bytes(), ss::SsCipherType::AES_256_GCM_2022, 32);
    Check2022(target, source, payload.Bytes(), ss::SsCipherType::CHACHA20_POLY1305_2022, 32);
    Check2022(target, source, payload.Bytes(), ss::SsCipherType::AES_128_GCM_2022, 16, true);
    Check2022(target, source, payload.Bytes(), ss::SsCipherType::AES_256_GCM_2022, 32, true);
}

TEST(ShadowsocksUdpDatagram, AuthenticatedShortDomainDatagrams) {
    for (std::string_view host : {"a", "ab"}) {
        SCOPED_TRACE(host);
        const TargetAddress target(host, 54321);
        for (size_t length : {size_t{0}, size_t{1}}) {
            SCOPED_TRACE(length);
            const std::vector<uint8_t> source(length, 0x7b);
            const auto packet = MakePayload(source, target);
            const buf::ContiguousBufferView payload(packet);
            for (std::string_view method : {"aes-128-gcm", "aes-256-gcm", "chacha20-poly1305"}) {
                const auto cipher = ss::ParseCipherMethod(method);
                Check(cipher.has_value(), "test cipher unavailable");
                CheckClassic(target, source, payload.Bytes(), *cipher);
            }
            Check2022(target, source, payload.Bytes(), ss::SsCipherType::AES_128_GCM_2022, 16);
            Check2022(target, source, payload.Bytes(), ss::SsCipherType::AES_256_GCM_2022, 32);
            Check2022(target, source, payload.Bytes(), ss::SsCipherType::CHACHA20_POLY1305_2022, 32);
            Check2022(target, source, payload.Bytes(), ss::SsCipherType::AES_128_GCM_2022, 16, true);
            Check2022(target, source, payload.Bytes(), ss::SsCipherType::AES_256_GCM_2022, 32, true);
        }
    }
}

TEST(ShadowsocksTcpWriter, FailedFrameRetiresWriterAndTransport) {
    for (std::string_view method : {"aes-128-gcm", "aes-256-gcm", "chacha20-poly1305",
                                    "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
                                    "2022-blake3-chacha20-poly1305"}) {
        SCOPED_TRACE(method);
        const auto cipher = ss::ParseCipherMethod(method);
        ASSERT_TRUE(cipher);
        for (const bool response : {false, true}) {
            SCOPED_TRACE(response);
            CheckTcpCancellationBeforeEncryption(*cipher, response);
            for (const bool scatter : {false, true}) {
                SCOPED_TRACE(scatter);
                for (const bool initialized : {false, true}) {
                    SCOPED_TRACE(initialized);
                    for (const auto fault : {WriteFault::PartialIo, WriteFault::PartialCancel,
                                             WriteFault::Allocation}) {
                        SCOPED_TRACE(static_cast<int>(fault));
                        CheckTcpWriterFailure(*cipher, response, scatter, initialized, fault);
                    }
                }
            }
        }
    }
}

TEST(ShadowsocksTcpWriter, FinishedWriterPreservesReverseRead) {
    for (std::string_view method : {"aes-128-gcm", "aes-256-gcm", "chacha20-poly1305",
                                    "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
                                    "2022-blake3-chacha20-poly1305"}) {
        SCOPED_TRACE(method);
        const auto cipher = ss::ParseCipherMethod(method);
        ASSERT_TRUE(cipher);
        for (const bool response : {false, true}) {
            SCOPED_TRACE(response);
            for (const bool initialized : {false, true}) {
                SCOPED_TRACE(initialized);
                for (const bool closed_before_start : {false, true}) {
                    SCOPED_TRACE(closed_before_start);
                    for (const bool scatter : {false, true}) {
                        SCOPED_TRACE(scatter);
                        CheckTcpFinishedWriter(*cipher, response, initialized, closed_before_start, scatter);
                    }
                }
            }
        }
    }
}
