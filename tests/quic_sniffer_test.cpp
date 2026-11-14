#include <gtest/gtest.h>

#include "sniff/sniffer.hpp"
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <algorithm>
#include <array>
#include <memory>
#include <span>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace {

using Bytes = std::vector<uint8_t>;

void RequireFixture(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

void U16(Bytes& bytes, size_t value) {
    bytes.push_back(static_cast<uint8_t>(value >> 8));
    bytes.push_back(static_cast<uint8_t>(value));
}

void Varint(Bytes& bytes, uint64_t value) {
    const size_t width = value < 64 ? 1 : value < 16384 ? 2 : value < (uint64_t{1} << 30) ? 4 : 8;
    const size_t start = bytes.size();
    for (size_t i = width; i != 0; --i)
        bytes.push_back(static_cast<uint8_t>(value >> ((i - 1) * 8)));
    bytes[start] |= static_cast<uint8_t>((width == 1 ? 0 : width == 2 ? 1 : width == 4 ? 2 : 3) << 6);
}

Bytes ClientHello(size_t padding = 0) {
    constexpr std::string_view host = "auth.openai.com";
    Bytes extensions;
    U16(extensions, 0);
    U16(extensions, host.size() + 5);
    U16(extensions, host.size() + 3);
    extensions.push_back(0);
    U16(extensions, host.size());
    extensions.insert(extensions.end(), host.begin(), host.end());
    if (padding != 0) {
        U16(extensions, 21);
        U16(extensions, padding);
        extensions.insert(extensions.end(), padding, 0);
    }
    Bytes body{3, 3};
    body.insert(body.end(), 32, 0x11);
    body.push_back(0);
    U16(body, 2);
    U16(body, 0x1301);
    body.push_back(1);
    body.push_back(0);
    U16(body, extensions.size());
    body.insert(body.end(), extensions.begin(), extensions.end());
    Bytes hello{1, static_cast<uint8_t>(body.size() >> 16),
                static_cast<uint8_t>(body.size() >> 8), static_cast<uint8_t>(body.size())};
    hello.insert(hello.end(), body.begin(), body.end());
    return hello;
}

std::array<uint8_t, 32> Hmac(std::span<const uint8_t> key, std::span<const uint8_t> data) {
    std::array<uint8_t, 32> digest{};
    unsigned int length = 0;
    RequireFixture(HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
               data.data(), data.size(), digest.data(), &length) && length == digest.size(),
          "fixture HMAC failed");
    return digest;
}

Bytes Expand(std::span<const uint8_t> secret, std::string_view label, size_t size) {
    Bytes info;
    U16(info, size);
    info.push_back(static_cast<uint8_t>(6 + label.size()));
    constexpr std::string_view prefix = "tls13 ";
    info.insert(info.end(), prefix.begin(), prefix.end());
    info.insert(info.end(), label.begin(), label.end());
    info.push_back(0);
    info.push_back(1);
    const auto digest = Hmac(secret, info);
    return Bytes(digest.begin(), digest.begin() + size);
}

// RFC 9001 / RFC 9369 client Initial protection, with deterministic DCID and PN.
Bytes Protect(Bytes plaintext, uint64_t pn = 0, uint32_t version = 1,
              uint8_t connection = 0, size_t pn_size = 2, bool pad = true) {
    constexpr std::array<uint8_t, 20> v1_salt{
        0x38,0x76,0x2c,0xf7,0xf5,0x59,0x34,0xb3,0x4d,0x17,
        0x9a,0xe6,0xa4,0xc8,0x0c,0xad,0xcc,0xbb,0x7f,0x0a};
    constexpr std::array<uint8_t, 20> v2_salt{
        0x0d,0xed,0xe3,0xde,0xf7,0x00,0xa6,0xdb,0x81,0x93,
        0x81,0xbe,0x6e,0x26,0x9d,0xcb,0xf9,0xbd,0x2e,0xd9};
    constexpr std::array<uint8_t, 20> draft_salt{
        0xaf,0xbf,0xec,0x28,0x99,0x93,0xd2,0x4c,0x9e,0x97,
        0x86,0xf1,0x9c,0x61,0x11,0xe0,0x43,0x90,0xa8,0x99};
    const bool v2 = version == 0x6b3343cf;
    std::array<uint8_t, 8> dcid{0x83,0x94,0xc8,0xf0,0x3e,0x51,0x57,connection};
    const auto initial = Hmac(v2 ? v2_salt : version == 1 ? v1_salt : draft_salt, dcid);
    const auto secret = Expand(initial, "client in", 32);
    const auto key = Expand(secret, v2 ? "quicv2 key" : "quic key", 16);
    const auto hp = Expand(secret, v2 ? "quicv2 hp" : "quic hp", 16);
    auto nonce = Expand(secret, v2 ? "quicv2 iv" : "quic iv", 12);
    for (size_t i = 0; i < 8; ++i)
        nonce[11 - i] ^= static_cast<uint8_t>(pn >> (i * 8));
    // Fixed two-byte Length: 18 header bytes before PN, then ciphertext + tag.
    plaintext.resize(std::max(plaintext.size(), pad ? 1250 - 18 - pn_size - 16 : size_t{4}), 0);
    Bytes packet{static_cast<uint8_t>((v2 ? 0xd0 : 0xc0) | (pn_size - 1)),
                 static_cast<uint8_t>(version >> 24), static_cast<uint8_t>(version >> 16),
                 static_cast<uint8_t>(version >> 8), static_cast<uint8_t>(version), 8};
    packet.insert(packet.end(), dcid.begin(), dcid.end());
    packet.push_back(0); // SCID length
    packet.push_back(0); // token length
    const size_t payload_size = pn_size + plaintext.size() + 16;
    RequireFixture(payload_size < 16384, "fixture payload exceeds two-byte Length");
    U16(packet, 0x4000 | payload_size);
    const size_t pn_offset = packet.size();
    for (size_t i = pn_size; i != 0; --i)
        packet.push_back(static_cast<uint8_t>(pn >> ((i - 1) * 8)));
    const size_t aad_size = packet.size();
    packet.resize(aad_size + plaintext.size() + 16);
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(
        EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    RequireFixture(ctx != nullptr, "fixture cipher allocation failed");
    int written = 0;
    int final = 0;
    RequireFixture(EVP_EncryptInit_ex(ctx.get(), EVP_aes_128_gcm(), nullptr, key.data(), nonce.data()) == 1 &&
          EVP_EncryptUpdate(ctx.get(), nullptr, &written, packet.data(), static_cast<int>(aad_size)) == 1 &&
          EVP_EncryptUpdate(ctx.get(), packet.data() + aad_size, &written,
                            plaintext.data(), static_cast<int>(plaintext.size())) == 1 &&
          EVP_EncryptFinal_ex(ctx.get(), packet.data() + aad_size + written, &final) == 1 &&
          static_cast<size_t>(written + final) == plaintext.size() &&
          EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, 16,
                              packet.data() + aad_size + plaintext.size()) == 1,
          "fixture GCM encryption failed");
    std::array<uint8_t, 16> mask{};
    RequireFixture(EVP_CIPHER_CTX_reset(ctx.get()) == 1 &&
          EVP_EncryptInit_ex(ctx.get(), EVP_aes_128_ecb(), nullptr, hp.data(), nullptr) == 1 &&
          EVP_CIPHER_CTX_set_padding(ctx.get(), 0) == 1 &&
          EVP_EncryptUpdate(ctx.get(), mask.data(), &written, packet.data() + pn_offset + 4, 16) == 1 &&
          written == 16, "fixture header protection failed");
    packet[0] ^= mask[0] & 0x0f;
    for (size_t i = 0; i < pn_size; ++i) packet[pn_offset + i] ^= mask[i + 1];
    return packet;
}

Bytes Crypto(std::span<const uint8_t> bytes, uint64_t offset = 0) {
    Bytes frames{6};
    Varint(frames, offset);
    Varint(frames, bytes.size());
    frames.insert(frames.end(), bytes.begin(), bytes.end());
    return frames;
}

template <class Parser>
::sniff::SniffResult Sniff(Parser& parser, const Bytes& packet) {
    if constexpr (requires { parser.Sniff(packet, ::common::Network::UDP); })
        return parser.Sniff(packet, ::common::Network::UDP);
    else
        return parser.Sniff(packet);
}

class QuicSnifferCases : public testing::Test {
protected:
    const Bytes hello = ClientHello();
    const Bytes large_hello = ClientHello(1800);
    const std::span<const uint8_t> large{large_hello};
    const Bytes first = Protect(Crypto(large.first(1000)), 0);
    const Bytes second = Protect(Crypto(large.subspan(1000), 1000), 1);

    static Bytes HandshakePacket() {
        Bytes packet{0xe0, 0, 0, 0, 1, 8,
                     0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0, 0, 20};
        packet.resize(packet.size() + 20, 0xa5);
        return packet;
    }
};

TEST_F(QuicSnifferCases, LongHeaderIdentityExposesVersionAndConnectionIds) {
    const auto packet = Protect(Crypto(hello));
    const auto header = ::sniff::InspectQuicLongHeader(packet);
    ASSERT_TRUE(header);
    EXPECT_EQ(header->version, 1u);
    EXPECT_EQ(header->type, ::sniff::QuicLongPacketType::Initial);
    ASSERT_EQ(header->destination.size, 8);
    EXPECT_TRUE(std::equal(
        header->destination.bytes.begin(),
        header->destination.bytes.begin() + 8,
        packet.begin() + 6));
    EXPECT_EQ(header->source.size, 0);
}

TEST_F(QuicSnifferCases, LongHeaderIdentityRecognizesRetryLayouts) {
    const Bytes version_one{
        0xf0, 0, 0, 0, 1,
        2, 0xaa, 0xbb,
        3, 0x11, 0x12, 0x13,
    };
    const auto first = ::sniff::InspectQuicLongHeader(version_one);
    ASSERT_TRUE(first);
    EXPECT_EQ(first->type, ::sniff::QuicLongPacketType::Retry);
    EXPECT_EQ(first->destination.size, 2);
    EXPECT_EQ(first->source.size, 3);

    const Bytes version_two{
        0xc0, 0x6b, 0x33, 0x43, 0xcf,
        1, 0xaa,
        2, 0x21, 0x22,
    };
    const auto second = ::sniff::InspectQuicLongHeader(version_two);
    ASSERT_TRUE(second);
    EXPECT_EQ(second->type, ::sniff::QuicLongPacketType::Retry);
    EXPECT_EQ(second->destination.size, 1);
    EXPECT_EQ(second->source.size, 2);

    EXPECT_FALSE(::sniff::InspectQuicLongHeader(
        Bytes{0xc0, 0, 0, 0, 1, 21}));
}

TEST_F(QuicSnifferCases, SupportedVersionsExtractDomain) {
    for (uint32_t version : {uint32_t{1}, uint32_t{0x6b3343cf}, uint32_t{0xff00001d}}) {
        ::sniff::QuicSniffer parser;
        {
    const auto result = Sniff(parser, Protect(Crypto(hello), 0, version));
    EXPECT_TRUE(result.success);
    EXPECT_FALSE(result.need_more);
    EXPECT_EQ(result.protocol, "quic");
    EXPECT_EQ(result.domain, "auth.openai.com");
}
    }
}

TEST_F(QuicSnifferCases, SupportedVersionsReassembleCrypto) {
    for (uint32_t version : {uint32_t{1}, uint32_t{0x6b3343cf}, uint32_t{0xff00001d}}) {
        ::sniff::QuicSniffer split;
        {
    const auto result = Sniff(split, Protect(Crypto(large.first(1000)), 0, version));
    EXPECT_FALSE(result.success);
    EXPECT_TRUE(result.need_more);
    EXPECT_EQ(result.protocol, "quic");
}
        {
    const auto result = Sniff(split, Protect(Crypto(large.subspan(1000), 1000), 1, version));
    EXPECT_TRUE(result.success);
    EXPECT_FALSE(result.need_more);
    EXPECT_EQ(result.protocol, "quic");
    EXPECT_EQ(result.domain, "auth.openai.com");
}
    }
}

TEST_F(QuicSnifferCases, DispatcherReassemblesAcrossDatagrams) {
    ::sniff::Sniffer parser;
    {
    const auto result = Sniff(parser, first);
    EXPECT_FALSE(result.success);
    EXPECT_TRUE(result.need_more);
    EXPECT_EQ(result.protocol, "quic");
}
    {
    const auto result = Sniff(parser, second);
    EXPECT_TRUE(result.success);
    EXPECT_FALSE(result.need_more);
    EXPECT_EQ(result.protocol, "quic");
    EXPECT_EQ(result.domain, "auth.openai.com");
}
}

TEST_F(QuicSnifferCases, ReorderedDuplicateDoesNotFillMissingPrefix) {
    ::sniff::QuicSniffer parser;
    {
    const auto result = Sniff(parser, second);
    EXPECT_FALSE(result.success);
    EXPECT_TRUE(result.need_more);
    EXPECT_EQ(result.protocol, "quic");
}
    {
    const auto result = Sniff(parser, second);
    EXPECT_FALSE(result.success);
    EXPECT_TRUE(result.need_more);
    EXPECT_EQ(result.protocol, "quic");
} // exact duplicate, including PN
    {
    const auto result = Sniff(parser, first);
    EXPECT_TRUE(result.success);
    EXPECT_FALSE(result.need_more);
    EXPECT_EQ(result.protocol, "quic");
    EXPECT_EQ(result.domain, "auth.openai.com");
}
}

TEST_F(QuicSnifferCases, CryptoHolesMustArriveBeforeSuccess) {
    ::sniff::QuicSniffer parser;
    const auto bytes = std::span<const uint8_t>(hello);
    {
    const auto result = Sniff(parser, Protect(Crypto(bytes.first(8)), 0));
    EXPECT_FALSE(result.success);
    EXPECT_TRUE(result.need_more);
    EXPECT_EQ(result.protocol, "quic");
}
    {
    const auto result = Sniff(parser, Protect(Crypto(bytes.subspan(20), 20), 2));
    EXPECT_FALSE(result.success);
    EXPECT_TRUE(result.need_more);
    EXPECT_EQ(result.protocol, "quic");
}
    // Missing TLS random bytes do not affect TLS syntax: zero-filled holes
    // used to produce a false domain before this final fragment arrived.
    {
    const auto result = Sniff(parser, Protect(Crypto(bytes.subspan(8, 12), 8), 1));
    EXPECT_TRUE(result.success);
    EXPECT_FALSE(result.need_more);
    EXPECT_EQ(result.protocol, "quic");
    EXPECT_EQ(result.domain, "auth.openai.com");
}
}

TEST_F(QuicSnifferCases, MatchingOverlapCompletesHello) {
    ::sniff::QuicSniffer parser;
    {
    const auto result = Sniff(parser, first);
    EXPECT_FALSE(result.success);
    EXPECT_TRUE(result.need_more);
    EXPECT_EQ(result.protocol, "quic");
}
    {
    const auto result = Sniff(parser, Protect(Crypto(large.subspan(900), 900), 2));
    EXPECT_TRUE(result.success);
    EXPECT_FALSE(result.need_more);
    EXPECT_EQ(result.protocol, "quic");
    EXPECT_EQ(result.domain, "auth.openai.com");
}
}

TEST_F(QuicSnifferCases, ConflictingOverlapIsTerminal) {
    ::sniff::QuicSniffer parser;
    {
    const auto result = Sniff(parser, first);
    EXPECT_FALSE(result.success);
    EXPECT_TRUE(result.need_more);
    EXPECT_EQ(result.protocol, "quic");
}
    auto conflicting = Bytes(large.begin() + 900, large.end());
    conflicting[0] ^= 1;
    {
    const auto result = Sniff(parser, Protect(Crypto(conflicting, 900), 2));
    EXPECT_FALSE(result.success);
    EXPECT_FALSE(result.need_more);
}
    {
    const auto result = Sniff(parser, second);
    EXPECT_FALSE(result.success);
    EXPECT_FALSE(result.need_more);
}
}

TEST_F(QuicSnifferCases, CoalescedInitialsCompleteHello) {
    ::sniff::QuicSniffer parser;
    auto coalesced = first;
    coalesced.insert(coalesced.end(), second.begin(), second.end());
    {
    const auto result = Sniff(parser, coalesced);
    EXPECT_TRUE(result.success);
    EXPECT_FALSE(result.need_more);
    EXPECT_EQ(result.protocol, "quic");
    EXPECT_EQ(result.domain, "auth.openai.com");
}
}

TEST_F(QuicSnifferCases, OpaqueCoalescedTrailersPreservePendingCrypto) {
    const auto handshake_packet = HandshakePacket();
    for (const Bytes& trailer : {Bytes(40, 0), Bytes{0x40, 1, 2, 3},
                                handshake_packet,
                                Bytes{0xf0, 0, 0, 0, 1, 0, 0,
                                      0, 0, 0, 0, 0, 0, 0, 0,
                                      0, 0, 0, 0, 0, 0, 0, 0}}) {
        ::sniff::QuicSniffer parser;
        auto packet = first;
        packet.insert(packet.end(), trailer.begin(), trailer.end());
        {
    const auto result = Sniff(parser, packet);
    EXPECT_FALSE(result.success);
    EXPECT_TRUE(result.need_more);
    EXPECT_EQ(result.protocol, "quic");
}
        {
    const auto result = Sniff(parser, second);
    EXPECT_TRUE(result.success);
    EXPECT_FALSE(result.need_more);
    EXPECT_EQ(result.protocol, "quic");
    EXPECT_EQ(result.domain, "auth.openai.com");
}
    }
}

TEST_F(QuicSnifferCases, ReorderedEarlyDataPreservesOnlyMatchingConnection) {
    const auto handshake_packet = HandshakePacket();
    // 0-RTT ciphertext is opaque to the Initial sniffer, but a reordered
    // same-connection long-header datagram must not terminate reassembly.
    auto early = handshake_packet;
    early[0] = 0xd0;
    ::sniff::QuicSniffer standalone;
    {
    const auto result = Sniff(standalone, early);
    EXPECT_FALSE(result.success);
    EXPECT_FALSE(result.need_more);
}
    ::sniff::QuicSniffer pending;
    {
    const auto result = Sniff(pending, first);
    EXPECT_FALSE(result.success);
    EXPECT_TRUE(result.need_more);
    EXPECT_EQ(result.protocol, "quic");
}
    {
    const auto result = Sniff(pending, early);
    EXPECT_FALSE(result.success);
    EXPECT_TRUE(result.need_more);
    EXPECT_EQ(result.protocol, "quic");
}
    {
    const auto result = Sniff(pending, second);
    EXPECT_TRUE(result.success);
    EXPECT_FALSE(result.need_more);
    EXPECT_EQ(result.protocol, "quic");
    EXPECT_EQ(result.domain, "auth.openai.com");
}
    early[13] = 1;
    ::sniff::QuicSniffer unrelated;
    {
    const auto result = Sniff(unrelated, first);
    EXPECT_FALSE(result.success);
    EXPECT_TRUE(result.need_more);
    EXPECT_EQ(result.protocol, "quic");
}
    {
    const auto result = Sniff(unrelated, early);
    EXPECT_FALSE(result.success);
    EXPECT_FALSE(result.need_more);
}
}

TEST_F(QuicSnifferCases, ConnectionOrVersionChangeIsTerminal) {
    for (bool change_version : {false, true}) {
        ::sniff::QuicSniffer parser;
        {
    const auto result = Sniff(parser, first);
    EXPECT_FALSE(result.success);
    EXPECT_TRUE(result.need_more);
    EXPECT_EQ(result.protocol, "quic");
}
        {
    const auto result = Sniff(parser, Protect(Crypto(large.subspan(1000), 1000), 1,
                                         change_version ? 0x6b3343cf : 1,
                                         change_version ? 0 : 1));
    EXPECT_FALSE(result.success);
    EXPECT_FALSE(result.need_more);
}
        {
    const auto result = Sniff(parser, second);
    EXPECT_FALSE(result.success);
    EXPECT_FALSE(result.need_more);
}
    }
}

TEST_F(QuicSnifferCases, NonInitialInputIsTerminal) {
    for (const Bytes& invalid : {Bytes{0, 1, 2, 3, 4, 5, 6, 7},
                                Bytes{0xc0, 0, 0, 0, 2, 0, 0},
                                Bytes{0x16, 3, 1, 0, 1}}) {
        ::sniff::Sniffer parser;
        {
    const auto result = Sniff(parser, invalid);
    EXPECT_FALSE(result.success);
    EXPECT_FALSE(result.need_more);
}
        ::sniff::QuicSniffer pending;
        {
    const auto result = Sniff(pending, first);
    EXPECT_FALSE(result.success);
    EXPECT_TRUE(result.need_more);
    EXPECT_EQ(result.protocol, "quic");
}
        {
    const auto result = Sniff(pending, invalid);
    EXPECT_FALSE(result.success);
    EXPECT_FALSE(result.need_more);
}
        {
    const auto result = Sniff(pending, second);
    EXPECT_FALSE(result.success);
    EXPECT_FALSE(result.need_more);
}
    }
}

TEST_F(QuicSnifferCases, UnauthenticatedOrTruncatedInitialFails) {
    for (bool truncate : {false, true}) {
        auto invalid = second;
        if (truncate) invalid.pop_back();
        else invalid.back() ^= 1;
        ::sniff::QuicSniffer parser;
        {
    const auto result = Sniff(parser, first);
    EXPECT_FALSE(result.success);
    EXPECT_TRUE(result.need_more);
    EXPECT_EQ(result.protocol, "quic");
}
        {
    const auto result = Sniff(parser, invalid);
    EXPECT_FALSE(result.success);
    EXPECT_FALSE(result.need_more);
}
    }
}

TEST_F(QuicSnifferCases, PacketNumberWrapReconstructsNonce) {
    ::sniff::QuicSniffer parser;
    const auto prefix = Protect(Crypto(large.first(1000)), 255, 1, 0, 1);
    {
    const auto result = Sniff(parser, prefix);
    EXPECT_FALSE(result.success);
    EXPECT_TRUE(result.need_more);
    EXPECT_EQ(result.protocol, "quic");
}
    {
    const auto result = Sniff(parser, Protect(Crypto(large.subspan(1000), 1000), 256, 1, 0, 1));
    EXPECT_TRUE(result.success);
    EXPECT_FALSE(result.need_more);
    EXPECT_EQ(result.protocol, "quic");
    EXPECT_EQ(result.domain, "auth.openai.com");
}
}

TEST_F(QuicSnifferCases, FragmentedTlsHeaderReassembles) {
    ::sniff::QuicSniffer parser;
    {
    const auto result = Sniff(parser, Protect(Crypto(large.first(1)), 0));
    EXPECT_FALSE(result.success);
    EXPECT_TRUE(result.need_more);
    EXPECT_EQ(result.protocol, "quic");
}
    {
    const auto result = Sniff(parser, Protect(Crypto(std::span<const uint8_t>(hello).subspan(1), 1), 1));
    EXPECT_TRUE(result.success);
    EXPECT_FALSE(result.need_more);
    EXPECT_EQ(result.protocol, "quic");
    EXPECT_EQ(result.domain, "auth.openai.com");
}
}

TEST_F(QuicSnifferCases, ReorderedCryptoFramesReassemble) {
    ::sniff::QuicSniffer parser;
    auto frames = Crypto(std::span<const uint8_t>(hello).subspan(20), 20);
    const auto prefix = Crypto(std::span<const uint8_t>(hello).first(20));
    frames.insert(frames.end(), prefix.begin(), prefix.end());
    {
    const auto result = Sniff(parser, Protect(frames));
    EXPECT_TRUE(result.success);
    EXPECT_FALSE(result.need_more);
    EXPECT_EQ(result.protocol, "quic");
    EXPECT_EQ(result.domain, "auth.openai.com");
}
}

TEST_F(QuicSnifferCases, LargeAckVarintsDoNotCountAsCryptoOffsets) {
    // Large ACK integers are valid QUIC varints, not CRYPTO bounds.
    auto frames = Crypto(large.first(1000));
    frames.push_back(2);
    Varint(frames, uint64_t{1} << 40);
    Varint(frames, uint64_t{1} << 35);
    Varint(frames, 0);
    Varint(frames, 0);
    ::sniff::QuicSniffer parser;
    {
    const auto result = Sniff(parser, Protect(frames));
    EXPECT_FALSE(result.success);
    EXPECT_TRUE(result.need_more);
    EXPECT_EQ(result.protocol, "quic");
}
    {
    const auto result = Sniff(parser, second);
    EXPECT_TRUE(result.success);
    EXPECT_FALSE(result.need_more);
    EXPECT_EQ(result.protocol, "quic");
    EXPECT_EQ(result.domain, "auth.openai.com");
}
}

TEST_F(QuicSnifferCases, CryptoOffsetBudgetIsBounded) {
    ::sniff::QuicSniffer parser;
    const std::array<uint8_t, 1> byte{0};
    {
    const auto result = Sniff(parser, Protect(Crypto(byte, 65535)));
    EXPECT_FALSE(result.success);
    EXPECT_TRUE(result.need_more);
    EXPECT_EQ(result.protocol, "quic");
}
    {
    const auto result = Sniff(parser, Protect(Crypto(byte, 65536), 1));
    EXPECT_FALSE(result.success);
    EXPECT_FALSE(result.need_more);
}
}

TEST_F(QuicSnifferCases, OversizedTlsLengthFails) {
    ::sniff::QuicSniffer parser;
    const std::array<uint8_t, 4> oversized{1, 1, 0, 0};
    {
    const auto result = Sniff(parser, Protect(Crypto(oversized)));
    EXPECT_FALSE(result.success);
    EXPECT_FALSE(result.need_more);
}
}

TEST_F(QuicSnifferCases, NonClientHelloFails) {
    ::sniff::QuicSniffer parser;
    auto invalid = hello;
    invalid[0] = 2;
    {
    const auto result = Sniff(parser, Protect(Crypto(invalid)));
    EXPECT_FALSE(result.success);
    EXPECT_FALSE(result.need_more);
}
}

TEST_F(QuicSnifferCases, InvalidServerNameFails) {
    ::sniff::QuicSniffer parser;
    auto invalid = hello;
    invalid.back() = '!'; // complete but invalid SNI is terminal
    {
    const auto result = Sniff(parser, Protect(Crypto(invalid)));
    EXPECT_FALSE(result.success);
    EXPECT_FALSE(result.need_more);
}
}

TEST_F(QuicSnifferCases, DuplicateBytesExhaustBudgetTerminally) {
    ::sniff::QuicSniffer parser;
    // The byte budget independently bounds duplicate retransmissions.
    for (size_t i = 0; i < 52; ++i) {
    const auto result = Sniff(parser, first);
    EXPECT_FALSE(result.success);
    EXPECT_TRUE(result.need_more);
    EXPECT_EQ(result.protocol, "quic");
}
    {
    const auto result = Sniff(parser, first);
    EXPECT_FALSE(result.success);
    EXPECT_FALSE(result.need_more);
}
    {
    const auto result = Sniff(parser, second);
    EXPECT_FALSE(result.success);
    EXPECT_FALSE(result.need_more);
}
}

TEST_F(QuicSnifferCases, FinalDatagramMayCrossByteBudget) {
    // A final already-read datagram may cross the byte budget and succeed.
    ::sniff::QuicSniffer crossing;
    for (size_t i = 0; i < 52; ++i) {
    const auto result = Sniff(crossing, first);
    EXPECT_FALSE(result.success);
    EXPECT_TRUE(result.need_more);
    EXPECT_EQ(result.protocol, "quic");
}
    {
    const auto result = Sniff(crossing, second);
    EXPECT_TRUE(result.success);
    EXPECT_FALSE(result.need_more);
    EXPECT_EQ(result.protocol, "quic");
    EXPECT_EQ(result.domain, "auth.openai.com");
}
}

TEST_F(QuicSnifferCases, DatagramCountBudgetIsBounded) {
    ::sniff::QuicSniffer parser;
    const auto tiny = Protect(Crypto(large.first(1)), 0, 1, 0, 2, false);
    for (size_t i = 0; i < 63; ++i) {
    const auto result = Sniff(parser, tiny);
    EXPECT_FALSE(result.success);
    EXPECT_TRUE(result.need_more);
    EXPECT_EQ(result.protocol, "quic");
}
    {
    const auto result = Sniff(parser, tiny);
    EXPECT_FALSE(result.success);
    EXPECT_FALSE(result.need_more);
}
    {
    const auto result = Sniff(parser, second);
    EXPECT_FALSE(result.success);
    EXPECT_FALSE(result.need_more);
}
}

TEST_F(QuicSnifferCases, OversizedDatagramFails) {
    ::sniff::QuicSniffer parser;
    {
    const auto result = Sniff(parser, Bytes(65537, 0xc0));
    EXPECT_FALSE(result.success);
    EXPECT_FALSE(result.need_more);
}
}

}  // namespace
