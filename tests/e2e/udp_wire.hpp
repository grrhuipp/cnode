#pragma once

#include "support.hpp"

#include <blake3.h>
#include <openssl/base64.h>
#include <openssl/evp.h>
#include <openssl/hkdf.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <sodium.h>

#include <arpa/inet.h>
#include <poll.h>
#include <sys/socket.h>

#include <array>
#include <cerrno>
#include <cstdlib>
#include <ctime>
#include <map>
#include <optional>
#include <stdexcept>
#include <utility>

namespace cnode::e2e::udp {
inline constexpr std::string_view SecondUser = "c942492e-7435-5e64-be5f-9ddb59c41922";
inline void Require(bool condition, std::string_view message) {
    if (!condition) throw std::runtime_error(std::string(message));
}
inline const unsigned char* Bytes(std::string_view s) {
    return reinterpret_cast<const unsigned char*>(s.data());
}
inline unsigned char* Bytes(std::string& s) { return reinterpret_cast<unsigned char*>(s.data()); }
inline std::string Random(size_t size) {
    std::string result(size, '\0');
    Require(RAND_bytes(Bytes(result), static_cast<int>(size)) == 1, "RAND_bytes failed");
    return result;
}
inline std::string Sequence(size_t size, size_t start = 0) {
    std::string result(size, '\0');
    for (size_t i = 0; i < size; ++i) result[i] = static_cast<char>(i + start);
    return result;
}
inline std::string LargePacket() {
    std::string result;
    result.reserve(20480);
    for (int i = 0; i < 80; ++i) result += Sequence(256);
    return result;
}
inline std::string Base64(std::string_view input) {
    std::string output(4 * ((input.size() + 2) / 3) + 1, '\0');
    int size = EVP_EncodeBlock(Bytes(output), Bytes(input), static_cast<int>(input.size()));
    Require(size >= 0, "base64 encoding failed");
    output.resize(static_cast<size_t>(size));
    return output;
}
inline std::string AesBlock(std::string_view key, std::string_view input, bool encrypt) {
    Require((key.size() == 16 || key.size() == 32) && input.size() == 16, "AES header lengths");
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    Require(ctx != nullptr, "AES context allocation");
    Require(EVP_CipherInit_ex(ctx.get(), key.size() == 16 ? EVP_aes_128_ecb() : EVP_aes_256_ecb(),
                             nullptr, Bytes(key), nullptr, encrypt) == 1,
            "AES init");
    Require(EVP_CIPHER_CTX_set_padding(ctx.get(), 0) == 1, "AES padding");
    std::string out(32, '\0');
    int size = 0, final = 0;
    Require(EVP_CipherUpdate(ctx.get(), Bytes(out), &size, Bytes(input), 16) == 1 &&
            EVP_CipherFinal_ex(ctx.get(), Bytes(out) + size, &final) == 1, "AES header operation");
    out.resize(static_cast<size_t>(size + final));
    return out;
}
inline std::string Gcm(std::string_view key, std::string_view nonce, std::string_view input,
                       bool encrypt, std::string_view aad = {}) {
    Require((key.size() == 16 || key.size() == 32) && nonce.size() == 12 &&
            (encrypt || input.size() >= 16), "GCM lengths");
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    Require(ctx != nullptr, "GCM context allocation");
    Require(EVP_CipherInit_ex(ctx.get(), key.size() == 16 ? EVP_aes_128_gcm() : EVP_aes_256_gcm(),
                             nullptr, Bytes(key), Bytes(nonce), encrypt) == 1,
            "GCM init");
    int size = 0, final = 0;
    if (!aad.empty()) Require(EVP_CipherUpdate(ctx.get(), nullptr, &size, Bytes(aad), static_cast<int>(aad.size())) == 1, "GCM AAD");
    size_t body = input.size() - (encrypt ? 0 : 16);
    std::string output(body + 32, '\0');
    Require(EVP_CipherUpdate(ctx.get(), Bytes(output), &size, Bytes(input), static_cast<int>(body)) == 1, "GCM body");
    if (!encrypt) Require(EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, 16,
                          const_cast<char*>(input.data() + body)) == 1, "GCM tag setup");
    Require(EVP_CipherFinal_ex(ctx.get(), Bytes(output) + size, &final) == 1, "GCM authentication");
    size += final;
    if (encrypt) {
        Require(EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, 16, output.data() + size) == 1, "GCM tag");
        size += 16;
    }
    output.resize(static_cast<size_t>(size));
    return output;
}
inline std::string LegacyKey(std::string_view salt, std::string_view password) {
    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned int size = 0;
    Require(EVP_Digest(password.data(), password.size(), digest.data(), &size, EVP_md5(), nullptr) == 1, "SS master key");
    std::string key(16, '\0');
    constexpr std::string_view info = "ss-subkey";
    Require(HKDF(Bytes(key), key.size(), EVP_sha1(), digest.data(), size, Bytes(salt), salt.size(), Bytes(info), info.size()) == 1,
            "SS HKDF");
    return key;
}
inline std::string LegacyEncrypt(std::string_view plain, std::string_view password = "secret") {
    auto salt = Random(16);
    return salt + Gcm(LegacyKey(salt, password), std::string(12, '\0'), plain, true);
}
inline std::string LegacyDecrypt(std::string_view packet, std::string_view password = "secret") {
    Require(packet.size() >= 32, "short SS packet");
    return Gcm(LegacyKey(packet.substr(0, 16), password), std::string(12, '\0'), packet.substr(16), false);
}
inline bool Readable(int fd, Milliseconds timeout) {
    pollfd item{fd, POLLIN, 0};
    int result;
    do { result = poll(&item, 1, static_cast<int>(timeout.count())); } while (result < 0 && errno == EINTR);
    Require(result >= 0, "poll failed");
    return result != 0;
}
struct Datagram {
    std::string payload;
    sockaddr_storage address{};
    socklen_t address_size = sizeof(address);
    uint16_t Port() const {
        return ntohs(address.ss_family == AF_INET
            ? reinterpret_cast<const sockaddr_in*>(&address)->sin_port
            : reinterpret_cast<const sockaddr_in6*>(&address)->sin6_port);
    }
    std::string Host() const {
        std::array<char, INET6_ADDRSTRLEN> text{};
        const void* value = address.ss_family == AF_INET
            ? static_cast<const void*>(&reinterpret_cast<const sockaddr_in*>(&address)->sin_addr)
            : static_cast<const void*>(&reinterpret_cast<const sockaddr_in6*>(&address)->sin6_addr);
        Require(inet_ntop(address.ss_family, value, text.data(), text.size()) != nullptr, "peer address");
        return text.data();
    }
    bool SameEndpoint(const Datagram& other) const { return Port() == other.Port() && Host() == other.Host(); }
};
inline Datagram Receive(const Socket& socket, Milliseconds timeout = 4s) {
    Require(Readable(socket.Fd(), timeout), "UDP receive deadline");
    Datagram packet;
    packet.payload.resize(65536);
    auto size = recvfrom(socket.Fd(), packet.payload.data(), packet.payload.size(), 0,
                         reinterpret_cast<sockaddr*>(&packet.address), &packet.address_size);
    Require(size >= 0, "recvfrom failed");
    // recvfrom == 0 is a complete empty UDP datagram, not stream EOF.
    packet.payload.resize(static_cast<size_t>(size));
    return packet;
}
inline void Reply(const Socket& socket, const Datagram& peer, std::string_view payload) {
    Require(sendto(socket.Fd(), payload.data(), payload.size(), 0,
                   reinterpret_cast<const sockaddr*>(&peer.address), peer.address_size) == static_cast<ssize_t>(payload.size()), "sendto failed");
}
struct PortReservation {
    Socket tcp;
    Socket udp;
    uint16_t port = 0;
    explicit PortReservation(bool native = false) {
        for (int attempt = 0; attempt < 64; ++attempt) {
            tcp = Socket::Listen();
            port = tcp.Port();
            if (!native) return;
            try { udp = Socket::BindUdp(port); return; }
            catch (const std::exception&) { tcp.Close(); }
        }
        throw std::runtime_error("no free TCP/UDP port");
    }
    void Release() { tcp.Close(); udp.Close(); }
};

class Client {
public:
    Client(uint16_t inbound, uint16_t destination, bool native, bool second = false,
           std::string host = "127.0.0.1", std::string cipher = {})
        : socket(std::make_shared<Socket>(native ? Socket::BindUdp() : Socket::Connect(inbound))),
          inbound_(inbound), native_(native), password_(second ? "second-secret" : "secret"),
          target_(SocksAddress(destination, host)), cipher_(std::move(cipher)),
          key_(Sequence(cipher_ == "aes" ? 16 : 32, second ? (cipher_ == "aes" ? 16 : 32) : 0)) {
        if (!native_) socket->Write(VlessRequest(destination, {}, 2, host, second ? SecondUser : UserId));
        if (cipher_ == "chacha") Require(sodium_init() >= 0, "sodium initialization");
    }
    std::string Encode(std::string_view payload) {
        if (cipher_.empty()) return LegacyEncrypt(target_ + std::string(payload), password_);
        const auto header = session + BigEndian(packet_id_++, 8);
        const auto body = std::string(1, '\0') + BigEndian(static_cast<uint64_t>(std::time(nullptr)), 8) +
                          std::string(2, '\0') + target_ + std::string(payload);
        if (cipher_ == "aes" || cipher_ == "aes256")
            return AesBlock(key_, header, true) + Gcm(Subkey(session), header.substr(4), body, true);
        auto nonce = Random(24);
        return nonce + XChaCha(nonce, header + body, true);
    }
    std::string Send(std::string_view payload) {
        if (!native_) { socket->Write(BigEndian(payload.size(), 2) + std::string(payload)); return {}; }
        auto packet = Encode(payload);
        SendRaw(packet);
        return packet;
    }
    void SendRaw(std::string_view packet) { socket->SendTo(packet, inbound_); }
    void Expect(std::string_view expected, Milliseconds timeout = 4s) {
        if (!native_) {
            if (!response_) { Require(socket->ReadExact(2, timeout) == std::string(2, '\0'), "VLESS response header"); response_ = true; }
            auto size = ReadBigEndian(socket->ReadExact(2, timeout));
            Require(socket->ReadExact(size, timeout) == expected, "VLESS UDP datagram changed");
            return;
        }
        auto packet = Receive(*socket, timeout).payload;
        if (cipher_.empty()) { Require(LegacyDecrypt(packet, password_) == target_ + std::string(expected), "native SS response changed"); return; }
        std::string header, plain;
        if (cipher_ == "aes" || cipher_ == "aes256") {
            Require(packet.size() >= 32, "short SS2022 response");
            header = AesBlock(key_, std::string_view(packet).substr(0, 16), false);
            plain = Gcm(Subkey(header.substr(0, 8)), header.substr(4), std::string_view(packet).substr(16), false);
        } else {
            Require(packet.size() >= 56, "short XChaCha response");
            auto decoded = XChaCha(std::string_view(packet).substr(0, 24), std::string_view(packet).substr(24), false);
            header = decoded.substr(0, 16); plain = decoded.substr(16);
        }
        Require(plain.size() >= 19 && plain[0] == 1 && plain.substr(9, 8) == session, "SS2022 response session header");
        auto timestamp = static_cast<int64_t>(ReadBigEndian(std::string_view(plain).substr(1, 8)));
        Require(std::abs(static_cast<int64_t>(std::time(nullptr)) - timestamp) <= 30, "SS2022 response timestamp");
        size_t offset = 19 + ReadBigEndian(std::string_view(plain).substr(17, 2));
        Require(offset <= plain.size() && plain.substr(offset) == target_ + std::string(expected), "SS2022 response identity or boundary changed");
        auto id = ReadBigEndian(std::string_view(header).substr(8));
        if (server_packet_id) {
            Require(server_session == header.substr(0, 8), "server session changed after handoff");
            Require(id > *server_packet_id, "server packet ID did not advance");
        }
        server_session = header.substr(0, 8); server_packet_id = id;
    }
    void Finish() { if (!native_) socket->ShutdownWrite(); }
    void ExpectEof() { if (!native_) Require(socket->Read(1, 2s).empty(), "unexpected trailing response"); }
    std::shared_ptr<Socket> socket;
    const std::string session = BigEndian(0x00123456789abcdeULL, 8);
    std::string server_session;
    std::optional<uint64_t> server_packet_id;
private:
    std::string Subkey(std::string_view session_id) const {
        blake3_hasher hasher;
        blake3_hasher_init_derive_key(&hasher, "shadowsocks 2022 session subkey");
        blake3_hasher_update(&hasher, key_.data(), key_.size());
        blake3_hasher_update(&hasher, session_id.data(), session_id.size());
        std::string result(key_.size(), '\0');
        blake3_hasher_finalize(&hasher, Bytes(result), result.size());
        return result;
    }
    std::string XChaCha(std::string_view nonce, std::string_view input, bool encrypt) const {
        std::string result(input.size() + 16, '\0');
        unsigned long long size = 0;
        int status = encrypt
            ? crypto_aead_xchacha20poly1305_ietf_encrypt(Bytes(result), &size, Bytes(input), input.size(), nullptr, 0, nullptr, Bytes(nonce), Bytes(key_))
            : crypto_aead_xchacha20poly1305_ietf_decrypt(Bytes(result), &size, nullptr, Bytes(input), input.size(), nullptr, 0, Bytes(nonce), Bytes(key_));
        Require(status == 0, "XChaCha authentication failed");
        result.resize(static_cast<size_t>(size));
        return result;
    }
    uint16_t inbound_;
    bool native_;
    bool response_ = false;
    std::string password_, target_, cipher_, key_;
    uint64_t packet_id_ = 0;
};

inline std::string Hmac(std::string_view key, std::string_view input) {
    std::string output(32, '\0'); unsigned int size = 0;
    Require(HMAC(EVP_sha256(), key.data(), key.size(), Bytes(input), input.size(), Bytes(output), &size) != nullptr && size == 32, "QUIC HMAC");
    return output;
}
inline std::string QuicVarint(size_t value) {
    Require(value < 16384, "QUIC varint too large");
    return BigEndian(value < 64 ? value : value | 0x4000, value < 64 ? 1 : 2);
}
inline std::array<std::string, 2> QuicInitials() {
    auto extension = [](unsigned kind, std::string_view data) { return BigEndian(kind, 2) + BigEndian(data.size(), 2) + std::string(data); };
    using namespace std::string_literals;
    std::string name = "fragmented-quic.test";
    auto server_name = "\0"s + BigEndian(name.size(), 2) + name;
    auto extensions = extension(43, "\2\3\4"s) + extension(10, "\0\2\0\x1d"s) +
        extension(13, "\0\4\x08\4\4\3"s) + extension(51, "\0\x24\0\x1d\0\x20"s + Sequence(32)) +
        extension(16, "\0\3\2h3"s) + extension(57, "\x0f\0"s) + extension(21, std::string(1700, '\0')) +
        extension(0, BigEndian(server_name.size(), 2) + server_name);
    auto hello = "\3\3"s + Sequence(32) + "\0\0\2\x13\1\1\0"s + BigEndian(extensions.size(), 2) + extensions;
    hello = "\1"s + BigEndian(hello.size(), 3) + hello;
    auto dcid = "\x83\x94\xc8\xf0\x3e\x51\x57\x08"s;
    auto secret = Hmac("\x38\x76\x2c\xf7\xf5\x59\x34\xb3\x4d\x17\x9a\xe6\xa4\xc8\x0c\xad\xcc\xbb\x7f\x0a"s, dcid);
    auto expand = [](std::string_view value, std::string label, size_t size) {
        label = "tls13 " + label;
        return Hmac(value, BigEndian(size, 2) + BigEndian(label.size(), 1) + label + std::string("\0\1", 2)).substr(0, size);
    };
    secret = expand(secret, "client in", 32);
    auto key = expand(secret, "quic key", 16), iv = expand(secret, "quic iv", 12), hp = expand(secret, "quic hp", 16);
    std::array<std::string, 2> packets;
    for (size_t number = 0; number < 2; ++number) {
        auto fragment = number == 0 ? hello.substr(0, 1000) : hello.substr(1000);
        auto prefix = "\xc1\0\0\0\1"s + BigEndian(dcid.size(), 1) + dcid + "\0\0"s;
        auto header = prefix + QuicVarint(1250 - prefix.size() - 2);
        size_t pn_offset = header.size();
        header += BigEndian(number, 2);
        auto crypto = "\6"s + QuicVarint(number == 0 ? 0 : 1000) + QuicVarint(fragment.size()) + fragment;
        Require(header.size() + 16 + crypto.size() <= 1250, "QUIC fragment exceeds packet");
        crypto.resize(1250 - header.size() - 16, '\0');
        auto nonce = iv; nonce.back() ^= static_cast<char>(number);
        auto packet = header + Gcm(key, nonce, crypto, true, header);
        auto mask = AesBlock(hp, packet.substr(pn_offset + 4, 16), true);
        packet[0] ^= mask[0] & 15; packet[pn_offset] ^= mask[1]; packet[pn_offset + 1] ^= mask[2];
        packets[number] = std::move(packet);
    }
    return packets;
}
} // namespace cnode::e2e::udp
