#include "ss_udp.hpp"
#include "shadowsocks_crypto.hpp"

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <bit>
#include <cstring>
#include <span>

namespace acpp::ss {

namespace {

constexpr size_t kSs2022UdpSeparateHeaderSize = 16;
constexpr size_t kSs2022UdpNonceSize = 24;
constexpr size_t kSs2022UdpSessionIdSize = 8;
constexpr size_t kSs2022UdpPacketIdSize = 8;
constexpr uint8_t kSs2022ClientPacket = 0;
constexpr uint8_t kSs2022ServerPacket = 1;

static std::array<uint8_t, 12> kZeroNonce{};

struct SsAddress {
    TargetAddress target;
    size_t consumed = 0;
};

struct Parsed2022Body {
    TargetAddress target;
    std::span<const uint8_t> payload;
    std::array<uint8_t, 8> client_session_id{};
};

std::optional<SsAddress> ParseSocks5Address(const uint8_t* data, size_t len) {
    if (len < 1) return std::nullopt;

    SsAddress result;
    size_t idx = 0;

    const uint8_t atyp = data[idx++];

    if (atyp == 0x01) {
        if (idx + 4 + 2 > len) return std::nullopt;
        net::ip::address_v4::bytes_type bytes{};
        std::memcpy(bytes.data(), data + idx, bytes.size());
        idx += 4;
        const uint16_t port = static_cast<uint16_t>((data[idx] << 8) | data[idx + 1]);
        idx += 2;
        result.target = TargetAddress(net::ip::make_address_v4(bytes), port);

    } else if (atyp == 0x03) {
        if (idx + 1 > len) return std::nullopt;
        const size_t name_len = data[idx++];
        if (idx + name_len + 2 > len) return std::nullopt;
        std::string domain(reinterpret_cast<const char*>(data + idx), name_len);
        idx += name_len;
        const uint16_t port = static_cast<uint16_t>((data[idx] << 8) | data[idx + 1]);
        idx += 2;
        result.target = TargetAddress(std::string_view(domain.data(), domain.size()), port);

    } else if (atyp == 0x04) {
        if (idx + 16 + 2 > len) return std::nullopt;
        net::ip::address_v6::bytes_type bytes{};
        std::memcpy(bytes.data(), data + idx, bytes.size());
        idx += bytes.size();
        const uint16_t port = static_cast<uint16_t>((data[idx] << 8) | data[idx + 1]);
        idx += 2;
        result.target = TargetAddress(net::ip::make_address_v6(bytes), port);
    } else {
        return std::nullopt;
    }

    result.consumed = idx;
    return result;
}

size_t Socks5AddressEncodedSize(const TargetAddress& addr) {
    if (addr.IsDomain()) {
        if (addr.host.size() > 255) {
            return 0;
        }
        return 1 + 1 + addr.host.size() + 2;
    }

    if (addr.resolved_addr) {
        if (addr.resolved_addr->is_v4()) {
            return 1 + 4 + 2;
        }
        if (addr.resolved_addr->is_v6()) {
            return 1 + 16 + 2;
        }
    }

    return 0;
}

size_t EncodeSocks5AddressTo(const TargetAddress& addr,
                             uint8_t* output,
                             size_t output_size) {
    const size_t needed = Socks5AddressEncodedSize(addr);
    if (needed == 0 || needed > output_size) {
        return 0;
    }

    size_t pos = 0;
    if (addr.IsDomain()) {
        if (addr.host.size() > 255) return 0;
        output[pos++] = 0x03;
        output[pos++] = static_cast<uint8_t>(addr.host.size());
        std::memcpy(output + pos, addr.host.data(), addr.host.size());
        pos += addr.host.size();
    } else {
        if (addr.resolved_addr && addr.resolved_addr->is_v4()) {
            output[pos++] = 0x01;
            auto bytes = addr.resolved_addr->to_v4().to_bytes();
            std::memcpy(output + pos, bytes.data(), bytes.size());
            pos += bytes.size();
        } else if (addr.resolved_addr && addr.resolved_addr->is_v6()) {
            output[pos++] = 0x04;
            auto bytes = addr.resolved_addr->to_v6().to_bytes();
            std::memcpy(output + pos, bytes.data(), bytes.size());
            pos += bytes.size();
        } else {
            return 0;
        }
    }

    output[pos++] = static_cast<uint8_t>(addr.port >> 8);
    output[pos++] = static_cast<uint8_t>(addr.port & 0xFF);
    return pos;
}

[[nodiscard]] bool AppendSpanToMultiBuffer(std::span<const uint8_t> data,
                                           buf::MultiBuffer& out) {
    size_t offset = 0;
    while (offset < data.size()) {
        buf::BufferGuard buffer{buf::Buffer::New()};
        if (!buffer) {
            return false;
        }
        const size_t n = std::min(data.size() - offset,
                                  static_cast<size_t>(buffer->Available()));
        std::memcpy(buffer->Tail().data(), data.data() + offset, n);
        buffer->Produce(static_cast<uint32_t>(n));
        out.push_back(buffer.release());
        offset += n;
    }
    return true;
}

[[nodiscard]] bool RandomBytes(std::span<uint8_t> out) {
    return out.empty() ||
           RAND_bytes(out.data(), static_cast<int>(out.size())) == 1;
}

[[nodiscard]] memory::ThreadLocalString SessionKeyFromClientId(
    std::span<const uint8_t, 8> client_session_id) {
    static constexpr char kHex[] = "0123456789abcdef";
    memory::ThreadLocalString out;
    out.reserve(7 + 16);
    out.append("ss2022:");
    for (uint8_t b : client_session_id) {
        out.push_back(kHex[b >> 4]);
        out.push_back(kHex[b & 0x0F]);
    }
    return out;
}

[[nodiscard]] bool BuildClassicUdpPlaintext(const TargetAddress& target,
                                            const uint8_t* payload,
                                            size_t payload_len,
                                            memory::ByteVector& plaintext) {
    const size_t addr_size = Socks5AddressEncodedSize(target);
    if (addr_size == 0) {
        return false;
    }
    plaintext.resize(addr_size + payload_len);
    const size_t encoded = EncodeSocks5AddressTo(
        target, plaintext.data(), plaintext.size());
    if (encoded != addr_size) {
        return false;
    }
    if (payload_len > 0) {
        std::memcpy(plaintext.data() + addr_size, payload, payload_len);
    }
    return true;
}

[[nodiscard]] bool Build2022ClientBodyPlaintext(const TargetAddress& target,
                                                const uint8_t* payload,
                                                size_t payload_len,
                                                memory::ByteVector& plaintext) {
    const size_t addr_size = Socks5AddressEncodedSize(target);
    if (addr_size == 0) {
        return false;
    }
    constexpr size_t kHeaderSize = 1 + 8 + 2;
    plaintext.resize(kHeaderSize + addr_size + payload_len);
    size_t pos = 0;
    plaintext[pos++] = kSs2022ClientPacket;
    PutU64BE(plaintext.data() + pos, UnixSecondsNow());
    pos += 8;
    PutU16BE(plaintext.data() + pos, 0);
    pos += 2;
    const size_t encoded = EncodeSocks5AddressTo(
        target, plaintext.data() + pos, plaintext.size() - pos);
    if (encoded != addr_size) {
        return false;
    }
    pos += encoded;
    if (payload_len > 0) {
        std::memcpy(plaintext.data() + pos, payload, payload_len);
    }
    return true;
}

[[nodiscard]] bool Build2022ServerBodyPlaintext(const TargetAddress& target,
                                                const uint8_t* payload,
                                                size_t payload_len,
                                                std::span<const uint8_t, 8> client_session_id,
                                                memory::ByteVector& plaintext) {
    const size_t addr_size = Socks5AddressEncodedSize(target);
    if (addr_size == 0) {
        return false;
    }
    constexpr size_t kHeaderSize = 1 + 8 + 8 + 2;
    plaintext.resize(kHeaderSize + addr_size + payload_len);
    size_t pos = 0;
    plaintext[pos++] = kSs2022ServerPacket;
    PutU64BE(plaintext.data() + pos, UnixSecondsNow());
    pos += 8;
    std::memcpy(plaintext.data() + pos, client_session_id.data(), client_session_id.size());
    pos += client_session_id.size();
    PutU16BE(plaintext.data() + pos, 0);
    pos += 2;
    const size_t encoded = EncodeSocks5AddressTo(
        target, plaintext.data() + pos, plaintext.size() - pos);
    if (encoded != addr_size) {
        return false;
    }
    pos += encoded;
    if (payload_len > 0) {
        std::memcpy(plaintext.data() + pos, payload, payload_len);
    }
    return true;
}

[[nodiscard]] std::optional<Parsed2022Body> Parse2022ClientBodyPlaintext(
    std::span<const uint8_t> plaintext,
    std::span<const uint8_t, 8> client_session_id) {
    constexpr size_t kMinHeader = 1 + 8 + 2;
    if (plaintext.size() < kMinHeader || plaintext[0] != kSs2022ClientPacket) {
        return std::nullopt;
    }
    if (!TimestampFresh(GetU64BE(plaintext.data() + 1), UnixSecondsNow())) {
        return std::nullopt;
    }
    const size_t padding_len = GetU16BE(plaintext.data() + 1 + 8);
    size_t pos = kMinHeader;
    if (pos + padding_len > plaintext.size()) {
        return std::nullopt;
    }
    pos += padding_len;

    auto addr = ParseSocks5Address(plaintext.data() + pos, plaintext.size() - pos);
    if (!addr) {
        return std::nullopt;
    }
    pos += addr->consumed;

    Parsed2022Body parsed;
    parsed.target = std::move(addr->target);
    parsed.payload = plaintext.subspan(pos);
    std::copy(client_session_id.begin(), client_session_id.end(),
              parsed.client_session_id.begin());
    return parsed;
}

[[nodiscard]] std::optional<Parsed2022Body> Parse2022ServerBodyPlaintext(
    std::span<const uint8_t> plaintext,
    std::span<const uint8_t, 8> expected_client_session_id) {
    constexpr size_t kMinHeader = 1 + 8 + 8 + 2;
    if (plaintext.size() < kMinHeader || plaintext[0] != kSs2022ServerPacket) {
        return std::nullopt;
    }
    if (!TimestampFresh(GetU64BE(plaintext.data() + 1), UnixSecondsNow())) {
        return std::nullopt;
    }
    if (!std::equal(expected_client_session_id.begin(),
                   expected_client_session_id.end(),
                   plaintext.begin() + 1 + 8)) {
        return std::nullopt;
    }
    const size_t padding_len = GetU16BE(plaintext.data() + 1 + 8 + 8);
    size_t pos = kMinHeader;
    if (pos + padding_len > plaintext.size()) {
        return std::nullopt;
    }
    pos += padding_len;

    auto addr = ParseSocks5Address(plaintext.data() + pos, plaintext.size() - pos);
    if (!addr) {
        return std::nullopt;
    }
    pos += addr->consumed;

    Parsed2022Body parsed;
    parsed.target = std::move(addr->target);
    parsed.payload = plaintext.subspan(pos);
    std::copy(expected_client_session_id.begin(),
              expected_client_session_id.end(),
              parsed.client_session_id.begin());
    return parsed;
}

[[nodiscard]] bool AeadEncrypt(SsCipherType cipher_type,
                               std::span<const uint8_t> key,
                               std::span<const uint8_t, 12> nonce,
                               std::span<const uint8_t> plaintext,
                               uint8_t* output) {
    SsAeadCipher aead(cipher_type, key.data(), key.size());
    return aead.Encrypt(nonce.data(), plaintext.data(), plaintext.size(), output);
}

[[nodiscard]] bool AeadDecrypt(SsCipherType cipher_type,
                               std::span<const uint8_t> key,
                               std::span<const uint8_t, 12> nonce,
                               std::span<const uint8_t> ciphertext,
                               uint8_t* output) {
    SsAeadCipher aead(cipher_type, key.data(), key.size());
    return aead.Decrypt(nonce.data(), ciphertext.data(), ciphertext.size(), output);
}

[[nodiscard]] uint32_t Load32LE(const uint8_t* data) noexcept {
    return static_cast<uint32_t>(data[0]) |
           (static_cast<uint32_t>(data[1]) << 8) |
           (static_cast<uint32_t>(data[2]) << 16) |
           (static_cast<uint32_t>(data[3]) << 24);
}

void Store32LE(uint8_t* out, uint32_t value) noexcept {
    out[0] = static_cast<uint8_t>(value);
    out[1] = static_cast<uint8_t>(value >> 8);
    out[2] = static_cast<uint8_t>(value >> 16);
    out[3] = static_cast<uint8_t>(value >> 24);
}

void ChaChaQuarterRound(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) noexcept {
    a += b; d ^= a; d = std::rotl(d, 16);
    c += d; b ^= c; b = std::rotl(b, 12);
    a += b; d ^= a; d = std::rotl(d, 8);
    c += d; b ^= c; b = std::rotl(b, 7);
}

[[nodiscard]] bool HChaCha20(std::span<const uint8_t> key,
                             std::span<const uint8_t, 16> nonce,
                             std::span<uint8_t, 32> out) {
    if (key.size() != 32) {
        return false;
    }
    std::array<uint32_t, 16> state{
        0x61707865U, 0x3320646eU, 0x79622d32U, 0x6b206574U,
        Load32LE(key.data() + 0),
        Load32LE(key.data() + 4),
        Load32LE(key.data() + 8),
        Load32LE(key.data() + 12),
        Load32LE(key.data() + 16),
        Load32LE(key.data() + 20),
        Load32LE(key.data() + 24),
        Load32LE(key.data() + 28),
        Load32LE(nonce.data() + 0),
        Load32LE(nonce.data() + 4),
        Load32LE(nonce.data() + 8),
        Load32LE(nonce.data() + 12),
    };

    for (int i = 0; i < 10; ++i) {
        ChaChaQuarterRound(state[0], state[4], state[8], state[12]);
        ChaChaQuarterRound(state[1], state[5], state[9], state[13]);
        ChaChaQuarterRound(state[2], state[6], state[10], state[14]);
        ChaChaQuarterRound(state[3], state[7], state[11], state[15]);
        ChaChaQuarterRound(state[0], state[5], state[10], state[15]);
        ChaChaQuarterRound(state[1], state[6], state[11], state[12]);
        ChaChaQuarterRound(state[2], state[7], state[8], state[13]);
        ChaChaQuarterRound(state[3], state[4], state[9], state[14]);
    }

    Store32LE(out.data() + 0, state[0]);
    Store32LE(out.data() + 4, state[1]);
    Store32LE(out.data() + 8, state[2]);
    Store32LE(out.data() + 12, state[3]);
    Store32LE(out.data() + 16, state[12]);
    Store32LE(out.data() + 20, state[13]);
    Store32LE(out.data() + 24, state[14]);
    Store32LE(out.data() + 28, state[15]);
    return true;
}

[[nodiscard]] bool XChaCha20Poly1305Crypt(bool encrypt,
                                          std::span<const uint8_t> key,
                                          std::span<const uint8_t, 24> nonce,
                                          std::span<const uint8_t> input,
                                          uint8_t* output) {
    std::array<uint8_t, 32> subkey{};
    std::array<uint8_t, 16> hnonce{};
    std::memcpy(hnonce.data(), nonce.data(), hnonce.size());
    if (!HChaCha20(key, hnonce, subkey)) {
        return false;
    }

    std::array<uint8_t, 12> ietf_nonce{};
    std::memcpy(ietf_nonce.data() + 4, nonce.data() + 16, 8);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return false;
    }

    const EVP_CIPHER* cipher = EVP_chacha20_poly1305();
    int out_len = 0;
    int final_len = 0;
    bool ok = false;
    if (encrypt) {
        ok =
            EVP_EncryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr) == 1 &&
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN,
                                static_cast<int>(ietf_nonce.size()), nullptr) == 1 &&
            EVP_EncryptInit_ex(ctx, nullptr, nullptr, subkey.data(), ietf_nonce.data()) == 1 &&
            EVP_EncryptUpdate(ctx, output, &out_len,
                              input.data(), static_cast<int>(input.size())) == 1 &&
            EVP_EncryptFinal_ex(ctx, output + out_len, &final_len) == 1 &&
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16,
                                output + input.size()) == 1;
    } else if (input.size() >= SsAeadCipher::kTagSize) {
        const size_t data_len = input.size() - SsAeadCipher::kTagSize;
        const uint8_t* tag = input.data() + data_len;
        ok =
            EVP_DecryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr) == 1 &&
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN,
                                static_cast<int>(ietf_nonce.size()), nullptr) == 1 &&
            EVP_DecryptInit_ex(ctx, nullptr, nullptr, subkey.data(), ietf_nonce.data()) == 1 &&
            EVP_DecryptUpdate(ctx, output, &out_len,
                              input.data(), static_cast<int>(data_len)) == 1 &&
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16,
                                const_cast<uint8_t*>(tag)) == 1 &&
            EVP_DecryptFinal_ex(ctx, output + out_len, &final_len) == 1;
    }

    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

[[nodiscard]] bool XChaCha20Poly1305Encrypt(std::span<const uint8_t> key,
                                            std::span<const uint8_t, 24> nonce,
                                            std::span<const uint8_t> plaintext,
                                            uint8_t* output) {
    return XChaCha20Poly1305Crypt(true, key, nonce, plaintext, output);
}

[[nodiscard]] bool XChaCha20Poly1305Decrypt(std::span<const uint8_t> key,
                                            std::span<const uint8_t, 24> nonce,
                                            std::span<const uint8_t> ciphertext,
                                            uint8_t* output) {
    return XChaCha20Poly1305Crypt(false, key, nonce, ciphertext, output);
}

[[nodiscard]] std::optional<SsUdpDecodeResult> Make2022DecodeResult(
    const proxyman::inbound::UserStore::ShadowsocksCredential& user,
    size_t user_index,
    const SsCipherInfo& cipher_info,
    std::span<const uint8_t, 8> client_session_id,
    Parsed2022Body parsed) {

    auto state = std::make_shared<Ss2022UdpSessionState>();
    state->cipher_info = cipher_info;
    if (!state->key.assign(user.derived_key.span())) {
        return std::nullopt;
    }
    std::copy(client_session_id.begin(), client_session_id.end(),
              state->client_session_id.begin());
    if (!RandomBytes(state->server_session_id)) {
        return std::nullopt;
    }

    SsUdpDecodeResult result;
    result.target = std::move(parsed.target);
    result.session_key = SessionKeyFromClientId(client_session_id);
    result.user_index = user_index;
    result.reply_key = state->key;
    result.cipher_info = cipher_info;
    result.ss2022_session = std::move(state);
    if (!AppendSpanToMultiBuffer(parsed.payload, result.payload)) {
        return std::nullopt;
    }
    return result;
}

[[nodiscard]] std::optional<SsUdpDecodeResult> Decode2022UdpAesRequest(
    const uint8_t* datagram,
    size_t datagram_len,
    const proxyman::inbound::UserStore::ShadowsocksUsersView& users,
    const SsCipherInfo& cipher_info) {

    constexpr size_t kMinBodyPlain = 1 + 8 + 2 + 1 + 4 + 2;
    if (datagram_len < kSs2022UdpSeparateHeaderSize +
            kMinBodyPlain + SsAeadCipher::kTagSize) {
        return std::nullopt;
    }

    std::array<uint8_t, 16> encrypted_separate{};
    std::memcpy(encrypted_separate.data(), datagram, encrypted_separate.size());

    for (size_t i = 0; i < users.size(); ++i) {
        const auto& user = users[i];
        const bool has_identity = !user.identity_key.empty();
        const auto header_key = has_identity ? user.identity_key.span()
                                             : user.derived_key.span();
        if (header_key.empty()) {
            continue;
        }

        std::array<uint8_t, 16> separate{};
        if (!AesBlockCrypt(header_key, encrypted_separate, separate, false)) {
            continue;
        }

        size_t body_offset = kSs2022UdpSeparateHeaderSize;
        if (has_identity) {
            if (datagram_len < kSs2022UdpSeparateHeaderSize * 2 +
                    kMinBodyPlain + SsAeadCipher::kTagSize) {
                continue;
            }
            std::array<uint8_t, 16> identity_cipher{};
            std::memcpy(identity_cipher.data(),
                        datagram + kSs2022UdpSeparateHeaderSize,
                        identity_cipher.size());
            std::array<uint8_t, 16> identity_plain{};
            if (!AesBlockCrypt(header_key, identity_cipher, identity_plain, false)) {
                continue;
            }
            for (size_t j = 0; j < identity_plain.size(); ++j) {
                identity_plain[j] ^= separate[j];
            }

            std::array<uint8_t, 16> user_hash{};
            if (!Hash2022Psk(user.derived_key.span(), user_hash) ||
                !std::equal(identity_plain.begin(), identity_plain.end(), user_hash.begin())) {
                continue;
            }
            body_offset += kSs2022UdpSeparateHeaderSize;
        }

        const size_t ciphertext_len = datagram_len - body_offset;
        if (ciphertext_len < SsAeadCipher::kTagSize) {
            continue;
        }
        memory::ByteVector plaintext(ciphertext_len - SsAeadCipher::kTagSize);
        std::array<uint8_t, 32> subkey{};
        if (!Derive2022Subkey(user.derived_key.data(), user.derived_key.size,
                              separate.data(), kSs2022UdpSessionIdSize,
                              subkey.data())) {
            continue;
        }
        std::array<uint8_t, 12> nonce{};
        std::memcpy(nonce.data(), separate.data() + 4, nonce.size());
        if (!AeadDecrypt(cipher_info.type,
                         std::span<const uint8_t>(subkey.data(), cipher_info.key_size),
                         nonce,
                         std::span<const uint8_t>(datagram + body_offset, ciphertext_len),
                         plaintext.data())) {
            continue;
        }

        std::array<uint8_t, 8> client_session_id{};
        std::memcpy(client_session_id.data(), separate.data(), client_session_id.size());
        auto parsed = Parse2022ClientBodyPlaintext(plaintext, client_session_id);
        if (!parsed) {
            continue;
        }
        return Make2022DecodeResult(
            user, i, cipher_info, client_session_id, std::move(*parsed));
    }

    return std::nullopt;
}

[[nodiscard]] std::optional<SsUdpDecodeResult> Decode2022UdpChachaRequest(
    const uint8_t* datagram,
    size_t datagram_len,
    const proxyman::inbound::UserStore::ShadowsocksUsersView& users,
    const SsCipherInfo& cipher_info) {

    constexpr size_t kMinPlain =
        kSs2022UdpSessionIdSize + kSs2022UdpPacketIdSize + 1 + 8 + 2 + 1 + 4 + 2;
    if (datagram_len < kSs2022UdpNonceSize + kMinPlain + SsAeadCipher::kTagSize) {
        return std::nullopt;
    }

    std::array<uint8_t, 24> nonce{};
    std::memcpy(nonce.data(), datagram, nonce.size());
    const uint8_t* ciphertext = datagram + nonce.size();
    const size_t ciphertext_len = datagram_len - nonce.size();

    for (size_t i = 0; i < users.size(); ++i) {
        const auto& user = users[i];
        if (user.derived_key.size != 32) {
            continue;
        }
        memory::ByteVector plaintext(ciphertext_len - SsAeadCipher::kTagSize);
        if (!XChaCha20Poly1305Decrypt(
                user.derived_key.span(), nonce,
                std::span<const uint8_t>(ciphertext, ciphertext_len),
                plaintext.data())) {
            continue;
        }

        std::array<uint8_t, 8> client_session_id{};
        std::memcpy(client_session_id.data(), plaintext.data(), client_session_id.size());
        const auto body = std::span<const uint8_t>(plaintext).subspan(
            kSs2022UdpSessionIdSize + kSs2022UdpPacketIdSize);
        auto parsed = Parse2022ClientBodyPlaintext(body, client_session_id);
        if (!parsed) {
            continue;
        }
        return Make2022DecodeResult(
            user, i, cipher_info, client_session_id, std::move(*parsed));
    }

    return std::nullopt;
}

[[nodiscard]] size_t EncodeClassicUdpPacketTo(
    const TargetAddress& target,
    const uint8_t* payload,
    size_t payload_len,
    std::span<const uint8_t> master_key,
    SsCipherType cipher_type,
    size_t key_size,
    size_t salt_size,
    uint8_t* output,
    size_t output_size) {

    if (key_size > 64 || salt_size > 64) {
        return 0;
    }
    if (master_key.size() < key_size) {
        return 0;
    }

    memory::ByteVector plaintext;
    if (!BuildClassicUdpPlaintext(target, payload, payload_len, plaintext)) {
        return 0;
    }

    const size_t total_size = salt_size + plaintext.size() + SsAeadCipher::kTagSize;
    if (output == nullptr || total_size > output_size) {
        return total_size;
    }

    uint8_t* salt = output;
    uint8_t* ciphertext = output + salt_size;

    if (!RandomBytes(std::span<uint8_t>(salt, salt_size))) {
        return 0;
    }

    std::array<uint8_t, 64> subkey{};
    if (!DeriveSubkey(master_key.data(), key_size,
                      salt, salt_size,
                      subkey.data())) {
        return 0;
    }

    if (!AeadEncrypt(cipher_type,
                     std::span<const uint8_t>(subkey.data(), key_size),
                     kZeroNonce,
                     plaintext,
                     ciphertext)) {
        return 0;
    }

    return total_size;
}

[[nodiscard]] size_t Encode2022UdpAesPacketTo(
    const TargetAddress& target,
    const uint8_t* payload,
    size_t payload_len,
    Ss2022UdpSessionState& state,
    std::span<const KeyBytes> psk_chain,
    bool response,
    uint8_t* output,
    size_t output_size) {

    const KeyBytes* body_key = &state.key;
    if (!response && !psk_chain.empty()) {
        body_key = &psk_chain.back();
    }
    if (body_key->empty()) {
        return 0;
    }

    memory::ByteVector body_plain;
    if (response) {
        if (!Build2022ServerBodyPlaintext(
                target, payload, payload_len, state.client_session_id, body_plain)) {
            return 0;
        }
    } else if (!Build2022ClientBodyPlaintext(
                   target, payload, payload_len, body_plain)) {
        return 0;
    }

    const size_t identity_count = response || psk_chain.size() < 2
        ? 0
        : psk_chain.size() - 1;
    const size_t total_size =
        kSs2022UdpSeparateHeaderSize +
        identity_count * kSs2022UdpSeparateHeaderSize +
        body_plain.size() +
        SsAeadCipher::kTagSize;
    if (output == nullptr || total_size > output_size) {
        return total_size;
    }

    std::array<uint8_t, 16> separate{};
    std::memcpy(separate.data(),
                response ? state.server_session_id.data() : state.client_session_id.data(),
                kSs2022UdpSessionIdSize);
    PutU64BE(separate.data() + kSs2022UdpSessionIdSize, state.next_packet_id);

    const KeyBytes* header_key = response ? &state.key : body_key;
    if (!response && !psk_chain.empty()) {
        header_key = &psk_chain.front();
    }
    if (header_key->empty() ||
        !AesBlockCrypt(header_key->span(), separate,
                       std::span<uint8_t, 16>(output, 16), true)) {
        return 0;
    }

    size_t pos = kSs2022UdpSeparateHeaderSize;
    if (!response && identity_count > 0) {
        for (size_t i = 0; i < identity_count; ++i) {
            std::array<uint8_t, 16> identity_plain{};
            if (!Hash2022Psk(psk_chain[i + 1].span(), identity_plain)) {
                return 0;
            }
            for (size_t j = 0; j < identity_plain.size(); ++j) {
                identity_plain[j] ^= separate[j];
            }
            if (!AesBlockCrypt(psk_chain[i].span(),
                               identity_plain,
                               std::span<uint8_t, 16>(output + pos, 16),
                               true)) {
                return 0;
            }
            pos += kSs2022UdpSeparateHeaderSize;
        }
    }

    std::array<uint8_t, 32> subkey{};
    const auto* session_id = response
        ? state.server_session_id.data()
        : state.client_session_id.data();
    if (!Derive2022Subkey(body_key->data(), body_key->size,
                          session_id, kSs2022UdpSessionIdSize,
                          subkey.data())) {
        return 0;
    }
    std::array<uint8_t, 12> nonce{};
    std::memcpy(nonce.data(), separate.data() + 4, nonce.size());
    if (!AeadEncrypt(state.cipher_info.type,
                     std::span<const uint8_t>(subkey.data(), state.cipher_info.key_size),
                     nonce,
                     body_plain,
                     output + pos)) {
        return 0;
    }

    ++state.next_packet_id;
    return total_size;
}

[[nodiscard]] size_t Encode2022UdpChachaPacketTo(
    const TargetAddress& target,
    const uint8_t* payload,
    size_t payload_len,
    Ss2022UdpSessionState& state,
    bool response,
    uint8_t* output,
    size_t output_size) {

    if (state.key.size != 32) {
        return 0;
    }

    memory::ByteVector body_plain;
    if (response) {
        if (!Build2022ServerBodyPlaintext(
                target, payload, payload_len, state.client_session_id, body_plain)) {
            return 0;
        }
    } else if (!Build2022ClientBodyPlaintext(
                   target, payload, payload_len, body_plain)) {
        return 0;
    }

    memory::ByteVector plaintext;
    plaintext.resize(kSs2022UdpSessionIdSize + kSs2022UdpPacketIdSize + body_plain.size());
    std::memcpy(plaintext.data(),
                response ? state.server_session_id.data() : state.client_session_id.data(),
                kSs2022UdpSessionIdSize);
    PutU64BE(plaintext.data() + kSs2022UdpSessionIdSize, state.next_packet_id);
    std::memcpy(plaintext.data() + kSs2022UdpSessionIdSize + kSs2022UdpPacketIdSize,
                body_plain.data(), body_plain.size());

    const size_t total_size =
        kSs2022UdpNonceSize + plaintext.size() + SsAeadCipher::kTagSize;
    if (output == nullptr || total_size > output_size) {
        return total_size;
    }

    std::array<uint8_t, 24> nonce{};
    if (!RandomBytes(nonce)) {
        return 0;
    }
    std::memcpy(output, nonce.data(), nonce.size());
    if (!XChaCha20Poly1305Encrypt(
            state.key.span(), nonce, plaintext, output + nonce.size())) {
        return 0;
    }

    ++state.next_packet_id;
    return total_size;
}

}  // namespace

std::optional<SsUdpDecodeResult> DecodeUdpPacket(
    const uint8_t* datagram,
    size_t datagram_len,
    const proxyman::inbound::UserStore::ShadowsocksUsersView& users,
    SsCipherType cipher_type,
    size_t key_size,
    size_t salt_size) {

    if (users.empty()) {
        return std::nullopt;
    }

    const SsCipherInfo cipher_info{cipher_type, key_size, salt_size};
    if (Is2022AesCipher(cipher_type)) {
        return Decode2022UdpAesRequest(datagram, datagram_len, users, cipher_info);
    }
    if (cipher_type == SsCipherType::CHACHA20_POLY1305_2022) {
        return Decode2022UdpChachaRequest(datagram, datagram_len, users, cipher_info);
    }

    if (key_size > 64 || salt_size > 64) {
        return std::nullopt;
    }

    if (datagram_len < salt_size + SsAeadCipher::kTagSize + 7) {
        return std::nullopt;
    }

    const uint8_t* salt = datagram;
    const uint8_t* cipher = datagram + salt_size;
    const size_t cipherlen = datagram_len - salt_size;
    const size_t plaintext_len = cipherlen - SsAeadCipher::kTagSize;
    memory::ByteVector plaintext(plaintext_len);

    for (size_t i = 0; i < users.size(); ++i) {
        const auto& user = users[i];

        std::array<uint8_t, 64> subkey{};
        if (!DeriveSubkey(user.derived_key.data(), key_size,
                          salt, salt_size,
                          subkey.data())) {
            continue;
        }

        if (!AeadDecrypt(cipher_type,
                         std::span<const uint8_t>(subkey.data(), key_size),
                         kZeroNonce,
                         std::span<const uint8_t>(cipher, cipherlen),
                         plaintext.data())) {
            continue;
        }

        auto addr = ParseSocks5Address(plaintext.data(), plaintext_len);
        if (!addr) {
            continue;
        }

        SsUdpDecodeResult result;
        result.target = std::move(addr->target);
        result.user_index = i;

        const size_t payload_offset = std::min(addr->consumed, plaintext_len);
        const size_t payload_size = plaintext_len - payload_offset;
        if (!AppendSpanToMultiBuffer(
                std::span<const uint8_t>(
                    plaintext.data() + payload_offset,
                    payload_size),
                result.payload)) {
            return std::nullopt;
        }

        return result;
    }

    return std::nullopt;
}

size_t EncodeUdpPacketTo(
    const TargetAddress& target,
    const uint8_t* payload,
    size_t payload_len,
    std::span<const uint8_t> master_key,
    SsCipherType cipher_type,
    size_t key_size,
    size_t salt_size,
    uint8_t* output,
    size_t output_size) {

    if (Is2022Cipher(cipher_type)) {
        return 0;
    }
    return EncodeClassicUdpPacketTo(
        target,
        payload,
        payload_len,
        master_key,
        cipher_type,
        key_size,
        salt_size,
        output,
        output_size);
}

std::optional<SsUdpDecodeResult> DecodeUdpPacketWithKey(
    const uint8_t* datagram,
    size_t datagram_len,
    std::span<const uint8_t> master_key,
    SsCipherType cipher_type,
    size_t key_size,
    size_t salt_size) {

    if (Is2022Cipher(cipher_type) ||
        key_size > 64 || salt_size > 64 ||
        master_key.size() < key_size) {
        return std::nullopt;
    }
    if (datagram_len < salt_size + SsAeadCipher::kTagSize + 7) {
        return std::nullopt;
    }

    const uint8_t* salt = datagram;
    const uint8_t* cipher = datagram + salt_size;
    const size_t cipherlen = datagram_len - salt_size;
    const size_t plaintext_len = cipherlen - SsAeadCipher::kTagSize;

    std::array<uint8_t, 64> subkey{};
    if (!DeriveSubkey(master_key.data(), key_size,
                      salt, salt_size,
                      subkey.data())) {
        return std::nullopt;
    }

    memory::ByteVector plaintext(plaintext_len);
    if (!AeadDecrypt(cipher_type,
                     std::span<const uint8_t>(subkey.data(), key_size),
                     kZeroNonce,
                     std::span<const uint8_t>(cipher, cipherlen),
                     plaintext.data())) {
        return std::nullopt;
    }

    auto addr = ParseSocks5Address(plaintext.data(), plaintext_len);
    if (!addr) {
        return std::nullopt;
    }

    SsUdpDecodeResult result;
    result.target = std::move(addr->target);
    result.reply_key.assign(master_key.first(key_size));
    result.cipher_info = SsCipherInfo{cipher_type, key_size, salt_size};

    const size_t payload_offset = std::min(addr->consumed, plaintext_len);
    if (!AppendSpanToMultiBuffer(
            std::span<const uint8_t>(
                plaintext.data() + payload_offset,
                plaintext_len - payload_offset),
            result.payload)) {
        return std::nullopt;
    }
    return result;
}

bool Init2022UdpSessionState(
    Ss2022UdpSessionState& state,
    const SsCipherInfo& cipher_info,
    const KeyBytes& key) {

    if (!Is2022Cipher(cipher_info) || key.empty()) {
        return false;
    }
    state = Ss2022UdpSessionState{};
    state.cipher_info = cipher_info;
    state.key = key;
    state.next_packet_id = 0;
    return RandomBytes(state.client_session_id) &&
           RandomBytes(state.server_session_id);
}

size_t Encode2022UdpRequestPacketTo(
    const TargetAddress& target,
    const uint8_t* payload,
    size_t payload_len,
    Ss2022UdpSessionState& state,
    std::span<const KeyBytes> psk_chain,
    uint8_t* output,
    size_t output_size) {

    if (Is2022AesCipher(state.cipher_info.type)) {
        return Encode2022UdpAesPacketTo(
            target, payload, payload_len, state, psk_chain,
            false, output, output_size);
    }
    if (state.cipher_info.type == SsCipherType::CHACHA20_POLY1305_2022) {
        return Encode2022UdpChachaPacketTo(
            target, payload, payload_len, state, false, output, output_size);
    }
    return 0;
}

size_t Encode2022UdpResponsePacketTo(
    const TargetAddress& target,
    const uint8_t* payload,
    size_t payload_len,
    Ss2022UdpSessionState& state,
    uint8_t* output,
    size_t output_size) {

    if (Is2022AesCipher(state.cipher_info.type)) {
        return Encode2022UdpAesPacketTo(
            target, payload, payload_len, state, {},
            true, output, output_size);
    }
    if (state.cipher_info.type == SsCipherType::CHACHA20_POLY1305_2022) {
        return Encode2022UdpChachaPacketTo(
            target, payload, payload_len, state, true, output, output_size);
    }
    return 0;
}

std::optional<SsUdpDecodeResult> Decode2022UdpResponsePacket(
    const uint8_t* datagram,
    size_t datagram_len,
    Ss2022UdpSessionState& state) {

    if (!Is2022Cipher(state.cipher_info) || state.key.empty()) {
        return std::nullopt;
    }

    memory::ByteVector plaintext;
    if (Is2022AesCipher(state.cipher_info.type)) {
        constexpr size_t kMinBodyPlain = 1 + 8 + 8 + 2 + 1 + 4 + 2;
        if (datagram_len < kSs2022UdpSeparateHeaderSize +
                kMinBodyPlain + SsAeadCipher::kTagSize) {
            return std::nullopt;
        }
        std::array<uint8_t, 16> encrypted_separate{};
        std::memcpy(encrypted_separate.data(), datagram, encrypted_separate.size());
        std::array<uint8_t, 16> separate{};
        if (!AesBlockCrypt(state.key.span(), encrypted_separate, separate, false)) {
            return std::nullopt;
        }
        const size_t body_offset = kSs2022UdpSeparateHeaderSize;
        const size_t ciphertext_len = datagram_len - body_offset;
        plaintext.resize(ciphertext_len - SsAeadCipher::kTagSize);

        std::array<uint8_t, 32> subkey{};
        if (!Derive2022Subkey(state.key.data(), state.key.size,
                              separate.data(), kSs2022UdpSessionIdSize,
                              subkey.data())) {
            return std::nullopt;
        }
        std::array<uint8_t, 12> nonce{};
        std::memcpy(nonce.data(), separate.data() + 4, nonce.size());
        if (!AeadDecrypt(state.cipher_info.type,
                         std::span<const uint8_t>(subkey.data(), state.cipher_info.key_size),
                         nonce,
                         std::span<const uint8_t>(datagram + body_offset, ciphertext_len),
                         plaintext.data())) {
            return std::nullopt;
        }
    } else if (state.cipher_info.type == SsCipherType::CHACHA20_POLY1305_2022) {
        constexpr size_t kMinPlain =
            kSs2022UdpSessionIdSize + kSs2022UdpPacketIdSize + 1 + 8 + 8 + 2 + 1 + 4 + 2;
        if (datagram_len < kSs2022UdpNonceSize + kMinPlain + SsAeadCipher::kTagSize) {
            return std::nullopt;
        }
        std::array<uint8_t, 24> nonce{};
        std::memcpy(nonce.data(), datagram, nonce.size());
        const uint8_t* ciphertext = datagram + nonce.size();
        const size_t ciphertext_len = datagram_len - nonce.size();
        memory::ByteVector decoded(ciphertext_len - SsAeadCipher::kTagSize);
        if (!XChaCha20Poly1305Decrypt(
                state.key.span(), nonce,
                std::span<const uint8_t>(ciphertext, ciphertext_len),
                decoded.data())) {
            return std::nullopt;
        }
        plaintext.assign(
            decoded.begin() + kSs2022UdpSessionIdSize + kSs2022UdpPacketIdSize,
            decoded.end());
    } else {
        return std::nullopt;
    }

    auto parsed = Parse2022ServerBodyPlaintext(plaintext, state.client_session_id);
    if (!parsed) {
        return std::nullopt;
    }

    SsUdpDecodeResult result;
    result.target = std::move(parsed->target);
    result.cipher_info = state.cipher_info;
    result.reply_key = state.key;
    if (!AppendSpanToMultiBuffer(parsed->payload, result.payload)) {
        return std::nullopt;
    }
    return result;
}

}  // namespace acpp::ss
