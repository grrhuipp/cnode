#include <gtest/gtest.h>

#include "sniff/sniffer.hpp"

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <algorithm>
#include <array>
#include <cstdio>
#include <memory>
#include <span>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace {

using Bytes = std::vector<uint8_t>;

void Check(bool condition, const char* message) {
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
    Check(HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
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
    Check(payload_size < 16384, "fixture payload exceeds two-byte Length");
    U16(packet, 0x4000 | payload_size);
    const size_t pn_offset = packet.size();
    for (size_t i = pn_size; i != 0; --i)
        packet.push_back(static_cast<uint8_t>(pn >> ((i - 1) * 8)));
    const size_t aad_size = packet.size();
    packet.resize(aad_size + plaintext.size() + 16);
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(
        EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    Check(ctx != nullptr, "fixture cipher allocation failed");
    int written = 0;
    int final = 0;
    Check(EVP_EncryptInit_ex(ctx.get(), EVP_aes_128_gcm(), nullptr, key.data(), nonce.data()) == 1 &&
          EVP_EncryptUpdate(ctx.get(), nullptr, &written, packet.data(), static_cast<int>(aad_size)) == 1 &&
          EVP_EncryptUpdate(ctx.get(), packet.data() + aad_size, &written,
                            plaintext.data(), static_cast<int>(plaintext.size())) == 1 &&
          EVP_EncryptFinal_ex(ctx.get(), packet.data() + aad_size + written, &final) == 1 &&
          static_cast<size_t>(written + final) == plaintext.size() &&
          EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, 16,
                              packet.data() + aad_size + plaintext.size()) == 1,
          "fixture GCM encryption failed");
    std::array<uint8_t, 16> mask{};
    Check(EVP_CIPHER_CTX_reset(ctx.get()) == 1 &&
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

void More(const ::SniffResult& result) {
    Check(!result.success && result.need_more && result.protocol == "quic",
          "incomplete authenticated CRYPTO must need more, never succeed prematurely");
}

void Failed(const ::SniffResult& result) {
    Check(!result.success && !result.need_more, "definite failure must not request more input");
}

void Domain(const ::SniffResult& result) {
    Check(result.success && !result.need_more && result.protocol == "quic" &&
          result.domain == "auth.openai.com", "complete Initial must yield auth.openai.com");
}

template <class Parser>
::SniffResult Unchanged(Parser& parser, const Bytes& packet) {
    const auto original = packet;
    ::SniffResult result;
    if constexpr (requires { parser.Sniff(packet, ::Network::UDP); })
        result = parser.Sniff(packet, ::Network::UDP);
    else
        result = parser.Sniff(packet);
    Check(packet == original, "sniffing must not modify original encrypted payload");
    return result;
}

void Run() {
    const auto hello = ClientHello();
    const auto large_hello = ClientHello(1800);
    const auto large = std::span<const uint8_t>(large_hello);
    const auto first = Protect(Crypto(large.first(1000)), 0);
    const auto second = Protect(Crypto(large.subspan(1000), 1000), 1);
    Check(first.size() == 1250 && second.size() == 1250, "fragment fixtures must be 1250-byte datagrams");
    for (uint32_t version : {uint32_t{1}, uint32_t{0x6b3343cf}, uint32_t{0xff00001d}}) {
        ::QuicSniffer parser;
        Domain(Unchanged(parser, Protect(Crypto(hello), 0, version)));
        ::QuicSniffer split;
        More(Unchanged(split, Protect(Crypto(large.first(1000)), 0, version)));
        Domain(Unchanged(split, Protect(Crypto(large.subspan(1000), 1000), 1, version)));
    }
    {
        ::Sniffer parser;
        More(Unchanged(parser, first));
        Domain(Unchanged(parser, second));
    }
    {
        ::QuicSniffer parser;
        More(Unchanged(parser, second));
        More(Unchanged(parser, second)); // exact duplicate, including PN
        Domain(Unchanged(parser, first));
    }
    {
        ::QuicSniffer parser;
        const auto bytes = std::span<const uint8_t>(hello);
        More(Unchanged(parser, Protect(Crypto(bytes.first(8)), 0)));
        More(Unchanged(parser, Protect(Crypto(bytes.subspan(20), 20), 2)));
        // Missing TLS random bytes do not affect TLS syntax: zero-filled holes
        // used to produce a false domain before this final fragment arrived.
        Domain(Unchanged(parser, Protect(Crypto(bytes.subspan(8, 12), 8), 1)));
    }
    {
        ::QuicSniffer parser;
        More(Unchanged(parser, first));
        Domain(Unchanged(parser, Protect(Crypto(large.subspan(900), 900), 2)));
    }
    {
        ::QuicSniffer parser;
        More(Unchanged(parser, first));
        auto conflicting = Bytes(large.begin() + 900, large.end());
        conflicting[0] ^= 1;
        Failed(Unchanged(parser, Protect(Crypto(conflicting, 900), 2)));
        Failed(Unchanged(parser, second));
    }
    {
        ::QuicSniffer parser;
        auto coalesced = first;
        coalesced.insert(coalesced.end(), second.begin(), second.end());
        Domain(Unchanged(parser, coalesced));
    }
    Bytes handshake_packet{0xe0, 0, 0, 0, 1, 8,
                           0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0, 0, 20};
    handshake_packet.resize(handshake_packet.size() + 20, 0xa5);
    for (const Bytes& trailer : {Bytes(40, 0), Bytes{0x40, 1, 2, 3},
                                handshake_packet,
                                Bytes{0xf0, 0, 0, 0, 1, 0, 0,
                                      0, 0, 0, 0, 0, 0, 0, 0,
                                      0, 0, 0, 0, 0, 0, 0, 0}}) {
        ::QuicSniffer parser;
        auto packet = first;
        packet.insert(packet.end(), trailer.begin(), trailer.end());
        More(Unchanged(parser, packet));
        Domain(Unchanged(parser, second));
    }
    {
        // 0-RTT ciphertext is opaque to the Initial sniffer, but a reordered
        // same-connection long-header datagram must not terminate reassembly.
        auto early = handshake_packet;
        early[0] = 0xd0;
        ::QuicSniffer standalone;
        Failed(Unchanged(standalone, early));
        ::QuicSniffer pending;
        More(Unchanged(pending, first));
        More(Unchanged(pending, early));
        Domain(Unchanged(pending, second));
        early[13] = 1;
        ::QuicSniffer unrelated;
        More(Unchanged(unrelated, first));
        Failed(Unchanged(unrelated, early));
    }
    for (bool change_version : {false, true}) {
        ::QuicSniffer parser;
        More(Unchanged(parser, first));
        Failed(Unchanged(parser, Protect(Crypto(large.subspan(1000), 1000), 1,
                                         change_version ? 0x6b3343cf : 1,
                                         change_version ? 0 : 1)));
        Failed(Unchanged(parser, second));
    }
    for (const Bytes& invalid : {Bytes{0, 1, 2, 3, 4, 5, 6, 7},
                                Bytes{0xc0, 0, 0, 0, 2, 0, 0},
                                Bytes{0x16, 3, 1, 0, 1}}) {
        ::Sniffer parser;
        Failed(Unchanged(parser, invalid));
        ::QuicSniffer pending;
        More(Unchanged(pending, first));
        Failed(Unchanged(pending, invalid));
        Failed(Unchanged(pending, second));
    }
    for (bool truncate : {false, true}) {
        auto invalid = second;
        if (truncate) invalid.pop_back();
        else invalid.back() ^= 1;
        ::QuicSniffer parser;
        More(Unchanged(parser, first));
        Failed(Unchanged(parser, invalid));
    }
    {
        ::QuicSniffer parser;
        const auto prefix = Protect(Crypto(large.first(1000)), 255, 1, 0, 1);
        More(Unchanged(parser, prefix));
        Domain(Unchanged(parser, Protect(Crypto(large.subspan(1000), 1000), 256, 1, 0, 1)));
    }
    {
        ::QuicSniffer parser;
        More(Unchanged(parser, Protect(Crypto(large.first(1)), 0)));
        Domain(Unchanged(parser, Protect(Crypto(std::span<const uint8_t>(hello).subspan(1), 1), 1)));
    }
    {
        ::QuicSniffer parser;
        auto frames = Crypto(std::span<const uint8_t>(hello).subspan(20), 20);
        const auto prefix = Crypto(std::span<const uint8_t>(hello).first(20));
        frames.insert(frames.end(), prefix.begin(), prefix.end());
        Domain(Unchanged(parser, Protect(frames)));
    }
    {
        // Large ACK integers are valid QUIC varints, not CRYPTO bounds.
        auto frames = Crypto(large.first(1000));
        frames.push_back(2);
        Varint(frames, uint64_t{1} << 40);
        Varint(frames, uint64_t{1} << 35);
        Varint(frames, 0);
        Varint(frames, 0);
        ::QuicSniffer parser;
        More(Unchanged(parser, Protect(frames)));
        Domain(Unchanged(parser, second));
    }
    {
        ::QuicSniffer parser;
        const std::array<uint8_t, 1> byte{0};
        More(Unchanged(parser, Protect(Crypto(byte, 65535))));
        Failed(Unchanged(parser, Protect(Crypto(byte, 65536), 1)));
    }
    {
        ::QuicSniffer parser;
        const std::array<uint8_t, 4> oversized{1, 1, 0, 0};
        Failed(Unchanged(parser, Protect(Crypto(oversized))));
    }
    {
        ::QuicSniffer parser;
        auto invalid = hello;
        invalid[0] = 2;
        Failed(Unchanged(parser, Protect(Crypto(invalid))));
    }
    {
        ::QuicSniffer parser;
        auto invalid = hello;
        invalid.back() = '!'; // complete but invalid SNI is terminal
        Failed(Unchanged(parser, Protect(Crypto(invalid))));
    }
    {
        ::QuicSniffer parser;
        // The byte budget independently bounds duplicate retransmissions.
        for (size_t i = 0; i < 52; ++i) More(Unchanged(parser, first));
        Failed(Unchanged(parser, first));
        Failed(Unchanged(parser, second));
    }
    {
        // A final already-read datagram may cross the byte budget and succeed.
        ::QuicSniffer crossing;
        for (size_t i = 0; i < 52; ++i) More(Unchanged(crossing, first));
        Domain(Unchanged(crossing, second));
    }
    {
        ::QuicSniffer parser;
        const auto tiny = Protect(Crypto(large.first(1)), 0, 1, 0, 2, false);
        for (size_t i = 0; i < 63; ++i) More(Unchanged(parser, tiny));
        Failed(Unchanged(parser, tiny));
        Failed(Unchanged(parser, second));
    }
    {
        ::QuicSniffer parser;
        Failed(Unchanged(parser, Bytes(65537, 0xc0)));
    }
}

}  // namespace

TEST(QuicSniffer, Contract) {
    try {
        ::Run();
        return;
    } catch (const std::exception& error) {
        std::fprintf(stderr, "%s\n", error.what());
        FAIL() << error.what();
    }
}
