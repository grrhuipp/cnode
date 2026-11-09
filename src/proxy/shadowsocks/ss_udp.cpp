#include "ss_udp.hpp"
#include "common/byte_reader.hpp"
#include "shadowsocks_crypto.hpp"
#include "common/address_codec.hpp"
#include "common/allocator.hpp"
#include "common/container_util.hpp"

#include <openssl/evp.h>
#include <openssl/aead.h>
#include <openssl/rand.h>
#include <openssl/siphash.h>

#include <algorithm>
#include <array>
#include <bit>
#include <cstring>
#include <limits>
#include <span>

namespace ss {

namespace {

constexpr size_t kSs2022UdpSeparateHeaderSize = 16;
constexpr size_t kSs2022UdpNonceSize = 24;
constexpr size_t kSs2022UdpSessionIdSize = 8;
constexpr size_t kSs2022UdpPacketIdSize = 8;
constexpr uint8_t kSs2022ClientPacket = 0;
constexpr uint8_t kSs2022ServerPacket = 1;
// SOCKS5 最短非空域名地址：ATYP、长度、一字节域名及两字节端口。
constexpr size_t kMinSocks5AddressSize = 1 + 1 + 1 + 2;

static std::array<uint8_t, 12> kZeroNonce{};

struct Parsed2022Body {
    TargetAddress target;
    std::span<const uint8_t> payload;
    std::optional<ForwardedMetadata> forwarded;
    std::array<uint8_t, 8> client_session_id{};
};


[[nodiscard]] bool RandomBytes(std::span<uint8_t> out) {
    return out.empty() ||
           RAND_bytes(out.data(), static_cast<int>(out.size())) == 1;
}


[[nodiscard]] bool WriteClassicUdpPlaintext(const TargetAddress& target,
                                            const uint8_t* payload,
                                            size_t payload_len,
                                            std::span<uint8_t> plaintext,
                                            ForwardedMetadataView forwarded = {}) noexcept {
    const size_t addr_size = AddressEncodedSize(target, forwarded);
    if (addr_size == 0 || plaintext.size() != addr_size + payload_len) {
        return false;
    }
    if (payload_len > 0) {
        std::memmove(plaintext.data() + addr_size, payload, payload_len);
    }
    return EncodeAddressTo(
               target, plaintext.data(), addr_size, AddressWireFormat::Socks5, forwarded) == addr_size;
}

[[nodiscard]] bool Write2022ClientBodyPlaintext(const TargetAddress& target,
                                                const uint8_t* payload,
                                                size_t payload_len,
                                                std::span<uint8_t> plaintext,
                                                ForwardedMetadataView forwarded = {}) noexcept {
    const size_t addr_size = AddressEncodedSize(target, forwarded);
    constexpr size_t kHeaderSize = 1 + 8 + 2;
    if (addr_size == 0 || plaintext.size() != kHeaderSize + addr_size + payload_len) {
        return false;
    }
    if (payload_len > 0) {
        std::memmove(plaintext.data() + kHeaderSize + addr_size, payload, payload_len);
    }
    size_t pos = 0;
    plaintext[pos++] = kSs2022ClientPacket;
    StoreU64BE(plaintext.data() + pos, UnixSecondsNow());
    pos += 8;
    StoreU16BE(plaintext.data() + pos, 0);
    pos += 2;
    return EncodeAddressTo(
               target, plaintext.data() + pos, addr_size, AddressWireFormat::Socks5, forwarded) == addr_size;
}

[[nodiscard]] bool Write2022ServerBodyPlaintext(const TargetAddress& target,
                                                const uint8_t* payload,
                                                size_t payload_len,
                                                std::span<const uint8_t, 8> client_session_id,
                                                std::span<uint8_t> plaintext) noexcept {
    const size_t addr_size = AddressEncodedSize(target);
    constexpr size_t kHeaderSize = 1 + 8 + 8 + 2;
    if (addr_size == 0 || plaintext.size() != kHeaderSize + addr_size + payload_len) {
        return false;
    }
    if (payload_len > 0) {
        std::memmove(plaintext.data() + kHeaderSize + addr_size, payload, payload_len);
    }
    size_t pos = 0;
    plaintext[pos++] = kSs2022ServerPacket;
    StoreU64BE(plaintext.data() + pos, UnixSecondsNow());
    pos += 8;
    std::memcpy(plaintext.data() + pos, client_session_id.data(), client_session_id.size());
    pos += client_session_id.size();
    StoreU16BE(plaintext.data() + pos, 0);
    pos += 2;
    return EncodeAddressTo(target, plaintext.data() + pos, addr_size, AddressWireFormat::Socks5) == addr_size;
}

[[nodiscard]] std::optional<Parsed2022Body> Parse2022ClientBodyPlaintext(
    std::span<const uint8_t> plaintext,
    std::span<const uint8_t, 8> client_session_id) {
    constexpr size_t kMinHeader = 1 + 8 + 2;
    if (plaintext.size() < kMinHeader || plaintext[0] != kSs2022ClientPacket) {
        return std::nullopt;
    }
    if (!TimestampFresh(LoadU64BE(plaintext.data() + 1), UnixSecondsNow())) {
        return std::nullopt;
    }
    const size_t padding_len = LoadU16BE(plaintext.data() + 1 + 8);
    size_t pos = kMinHeader;
    if (pos + padding_len > plaintext.size()) {
        return std::nullopt;
    }
    pos += padding_len;

    auto addr = DecodeAddress(
        std::span<const uint8_t>(plaintext.data() + pos, plaintext.size() - pos),
        AddressWireFormat::Socks5,
        {.require_non_empty_domain = true, .allow_metadata = true});
    if (addr.status != AddressDecodeStatus::Complete || !addr.target.IsValid()) {
        return std::nullopt;
    }
    pos += addr.consumed;

    Parsed2022Body parsed;
    parsed.target = std::move(addr.target);
    parsed.forwarded = std::move(addr.forwarded);
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
    if (!TimestampFresh(LoadU64BE(plaintext.data() + 1), UnixSecondsNow())) {
        return std::nullopt;
    }
    if (!std::equal(expected_client_session_id.begin(),
                   expected_client_session_id.end(),
                   plaintext.begin() + 1 + 8)) {
        return std::nullopt;
    }
    const size_t padding_len = LoadU16BE(plaintext.data() + 1 + 8 + 8);
    size_t pos = kMinHeader;
    if (pos + padding_len > plaintext.size()) {
        return std::nullopt;
    }
    pos += padding_len;

    auto addr = DecodeAddress(
        std::span<const uint8_t>(plaintext.data() + pos, plaintext.size() - pos),
        AddressWireFormat::Socks5,
        {.require_non_empty_domain = true, .allow_metadata = false});
    if (addr.status != AddressDecodeStatus::Complete || !addr.target.IsValid()) {
        return std::nullopt;
    }
    pos += addr.consumed;

    Parsed2022Body parsed;
    parsed.target = std::move(addr.target);
    parsed.payload = plaintext.subspan(pos);
    std::copy(expected_client_session_id.begin(),
              expected_client_session_id.end(),
              parsed.client_session_id.begin());
    return parsed;
}

[[nodiscard]] const EVP_AEAD* DatagramAead(SsCipherType type) noexcept {
    switch (BaseCipherType(type)) {
        case SsCipherType::AES_128_GCM: return EVP_aead_aes_128_gcm();
        case SsCipherType::AES_256_GCM: return EVP_aead_aes_256_gcm();
        case SsCipherType::CHACHA20_POLY1305: return EVP_aead_chacha20_poly1305();
        default: return nullptr;
    }
}

[[nodiscard]] bool AeadEncrypt(SsCipherType cipher_type,
                               std::span<const uint8_t> key,
                               std::span<const uint8_t, 12> nonce,
                               std::span<const uint8_t> plaintext,
                               uint8_t* output) {
    const auto* algorithm = DatagramAead(cipher_type);
    if (!algorithm || plaintext.size() >
            std::numeric_limits<size_t>::max() - SsAeadCipher::kTagSize) return false;
    // One datagram, one synchronous stack-owned AEAD context. No connection
    // cache or EVP_CIPHER_CTX allocation is needed for this bounded operation.
    // EVP_AEAD_CTX_init accepts uninitialized storage, including on failure.
    // Avoid clearing it before init; the post-operation cleanse remains required.
    EVP_AEAD_CTX context;
    size_t written = 0;
    const size_t capacity = plaintext.size() + SsAeadCipher::kTagSize;
    const bool ok = EVP_AEAD_CTX_init(&context, algorithm, key.data(), key.size(),
                                    SsAeadCipher::kTagSize, nullptr) == 1 &&
        EVP_AEAD_CTX_seal(&context, output, &written, capacity,
                         nonce.data(), nonce.size(), plaintext.data(), plaintext.size(),
                         nullptr, 0) == 1;
    EVP_AEAD_CTX_cleanup(&context);
    OPENSSL_cleanse(&context, sizeof(context));
    return ok && written == capacity;
}

[[nodiscard]] bool AeadDecrypt(SsCipherType cipher_type,
                               std::span<const uint8_t> key,
                               std::span<const uint8_t, 12> nonce,
                               std::span<const uint8_t> ciphertext,
                               uint8_t* output) {
    const auto* algorithm = DatagramAead(cipher_type);
    if (!algorithm || ciphertext.size() < SsAeadCipher::kTagSize) return false;
    EVP_AEAD_CTX context;
    size_t written = 0;
    const size_t capacity = ciphertext.size() - SsAeadCipher::kTagSize;
    const bool ok = EVP_AEAD_CTX_init(&context, algorithm, key.data(), key.size(),
                                    SsAeadCipher::kTagSize, nullptr) == 1 &&
        EVP_AEAD_CTX_open(&context, output, &written, capacity,
                         nonce.data(), nonce.size(), ciphertext.data(), ciphertext.size(),
                         nullptr, 0) == 1;
    EVP_AEAD_CTX_cleanup(&context);
    OPENSSL_cleanse(&context, sizeof(context));
    return ok && written == capacity;
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
    OPENSSL_cleanse(state.data(), sizeof(state));
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
        OPENSSL_cleanse(subkey.data(), subkey.size());
        return false;
    }

    std::array<uint8_t, 12> ietf_nonce{};
    std::memcpy(ietf_nonce.data() + 4, nonce.data() + 16, 8);
    const bool ok = encrypt
        ? AeadEncrypt(SsCipherType::CHACHA20_POLY1305, subkey, ietf_nonce, input, output)
        : AeadDecrypt(SsCipherType::CHACHA20_POLY1305, subkey, ietf_nonce, input, output);
    OPENSSL_cleanse(subkey.data(), subkey.size());
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

struct PlaintextScratch {
    buf::BufferGuard pooled;
    memory::ByteVector large;
    size_t len = 0;

    ~PlaintextScratch() noexcept {
        if (pooled) {
            OPENSSL_cleanse(pooled->Tail().data(), len);
        }
        if (!large.empty()) {
            OPENSSL_cleanse(large.data(), large.size());
        }
    }

    [[nodiscard]] uint8_t* Prepare(size_t size) {
        len = size;
        if (size <= buf::Buffer::kSize) {
            if (!pooled) {
                pooled = buf::BufferGuard{buf::Buffer::New()};
                if (!pooled) {
                    return nullptr;
                }
            } else {
                pooled->Reset();
            }
            return pooled->Tail().data();
        }
        pooled.reset();
        large.resize(size);
        return large.data();
    }

    [[nodiscard]] std::span<const uint8_t> Span() const noexcept {
        if (pooled) {
            return {pooled->Tail().data(), len};
        }
        return {large.data(), len};
    }

    [[nodiscard]] bool MoveSuffixTo(size_t offset, buf::MultiBuffer& out) {
        if (offset > len) {
            return false;
        }
        const size_t payload_len = len - offset;
        if (pooled) {
            if (offset != 0) {
                OPENSSL_cleanse(pooled->Tail().data(), offset);
            }
            pooled->Produce(static_cast<uint32_t>(len));
            pooled->Advance(static_cast<uint32_t>(offset));
            try {
                out.push_back(std::move(pooled));
                len = 0;
                return true;
            } catch (...) {
                return false;
            }
        }
        return buf::AppendSpanToMultiBuffer(
            std::span<const uint8_t>(large.data() + offset, payload_len), out);
    }
};

[[nodiscard]] std::optional<SsUdpDecodeResult> Make2022DecodeResult(
    size_t user_index,
    std::span<const uint8_t, 8> client_session_id,
    std::span<const uint8_t> authenticated_key,
    uint64_t packet_id,
    Parsed2022Body parsed,
    PlaintextScratch& scratch) {

    SsUdpDecodeResult result;
    result.target = std::move(parsed.target);
    result.forwarded = std::move(parsed.forwarded);
    uint64_t session_id = 0;
    for (uint8_t byte : client_session_id) session_id = (session_id << 8) | byte;
    result.session_id = session_id;
    result.packet_id = packet_id;
    if (!result.session_owner.assign(authenticated_key)) {
        return std::nullopt;
    }
    result.user_index = user_index;
    const auto full = scratch.Span();
    const size_t payload_offset = static_cast<size_t>(parsed.payload.data() - full.data());
    if (!scratch.MoveSuffixTo(payload_offset, result.payload) ||
        !buf::SetUdpTarget(result.payload, result.target)) {
        return std::nullopt;
    }
    return result;
}

[[nodiscard]] std::optional<SsUdpDecodeResult> Decode2022UdpAesRequest(
    const uint8_t* datagram,
    size_t datagram_len,
    const proxyman::inbound::UserStore::ShadowsocksUsersView& users,
    const SsCipherInfo& cipher_info,
    Ss2022UdpReplayCache& replay_cache,
    bool deferred_replay) {

    constexpr size_t kMinBodyPlain = 1 + 8 + 2 + kMinSocks5AddressSize;
    if (datagram_len < kSs2022UdpSeparateHeaderSize +
            kMinBodyPlain + SsAeadCipher::kTagSize) {
        return std::nullopt;
    }

    std::array<std::array<uint8_t, 16>, 2> headers{};
    // 按整个数组对象的字节表示写入，避免跨子数组构造 span 或复制 PSK 哈希。
    static_assert(sizeof(headers) == kSs2022UdpSeparateHeaderSize * 2);
    auto& separate = headers[0];
    auto& identity_hash = headers[1];
    struct CleanseIdentityHeaders {
        std::array<std::array<uint8_t, 16>, 2>& bytes;
        ~CleanseIdentityHeaders() noexcept {
            OPENSSL_cleanse(&bytes, sizeof(bytes));
        }
    } cleanse_headers{headers};
    PlaintextScratch scratch;
    for (size_t group = 0; group < users.size();) {
        const auto& first = users[group];
        const bool has_identity = !first.identity_key.empty();
        // Pure/nonidentity credentials are not hash-indexed: authenticate each
        // in snapshot order. Identity groups share both AES header operations.
        const size_t end = has_identity ? users.IdentityGroupEnd(group) : group + 1;
        size_t candidate = group;
        group = end;
        const auto& header_key = has_identity ? first.identity_key : first.derived_key;
        const size_t body_offset = has_identity
            ? kSs2022UdpSeparateHeaderSize * 2 : kSs2022UdpSeparateHeaderSize;
        if (datagram_len < body_offset + kMinBodyPlain + SsAeadCipher::kTagSize ||
            header_key.empty()) {
            continue;
        }
        const auto encrypted = std::span<const uint8_t>(datagram, body_offset);
        auto decrypted = std::span<uint8_t, 32>(reinterpret_cast<uint8_t*>(&headers), sizeof(headers));
        const bool decoded = has_identity
            ? AesBlocksCrypt<32>(header_key.span(), encrypted.first<32>(), decrypted, false)
            : AesBlocksCrypt<16>(header_key.span(), encrypted.first<16>(), separate, false);
        if (!decoded) continue;

        if (has_identity) {
            for (size_t j = 0; j < identity_hash.size(); ++j) {
                identity_hash[j] ^= separate[j];
            }
            candidate = users.IdentityHashLowerBound(candidate, end, identity_hash);
        }

        const size_t ciphertext_len = datagram_len - body_offset;
        if (ciphertext_len < SsAeadCipher::kTagSize) {
            continue;
        }
        for (; candidate < end; ++candidate) {
            const auto& user = users[candidate];
            if (has_identity &&
                CRYPTO_memcmp(identity_hash.data(), user.psk_hash.data(),
                              identity_hash.size()) != 0) {
                break;
            }
            // The hash only narrows candidates; every collision must pass AEAD.
            uint8_t* plain_dst = scratch.Prepare(ciphertext_len - SsAeadCipher::kTagSize);
            if (!plain_dst) {
                return std::nullopt;
            }
            std::array<uint8_t, 32> subkey{};
            if (!Derive2022Subkey(user.derived_key.data(), user.derived_key.size,
                                  separate.data(), kSs2022UdpSessionIdSize,
                                  subkey.data())) {
                OPENSSL_cleanse(subkey.data(), subkey.size());
                continue;
            }
            std::array<uint8_t, 12> nonce{};
            std::memcpy(nonce.data(), separate.data() + 4, nonce.size());
            const bool decrypted = AeadDecrypt(
                cipher_info.type,
                std::span<const uint8_t>(subkey.data(), cipher_info.key_size),
                nonce,
                std::span<const uint8_t>(datagram + body_offset, ciphertext_len),
                plain_dst);
            OPENSSL_cleanse(subkey.data(), subkey.size());
            if (!decrypted) {
                continue;
            }
            std::array<uint8_t, 8> client_session_id{};
            std::memcpy(client_session_id.data(), separate.data(), client_session_id.size());
            auto parsed = Parse2022ClientBodyPlaintext(scratch.Span(), client_session_id);
            if (!parsed) {
                return std::nullopt;
            }
            const uint64_t packet_id = LoadU64BE(
                separate.data() + kSs2022UdpSessionIdSize);
            if (!deferred_replay &&
                !replay_cache.Accept(user.derived_key.span(), client_session_id, packet_id)) {
                return std::nullopt;
            }
            return Make2022DecodeResult(
                candidate, client_session_id, user.derived_key.span(), packet_id,
                std::move(*parsed), scratch);
        }
    }

    return std::nullopt;
}

[[nodiscard]] std::optional<SsUdpDecodeResult> Decode2022UdpChachaRequest(
    const uint8_t* datagram,
    size_t datagram_len,
    const proxyman::inbound::UserStore::ShadowsocksUsersView& users,
    Ss2022UdpReplayCache& replay_cache,
    bool deferred_replay) {

    constexpr size_t kMinPlain =
        kSs2022UdpSessionIdSize + kSs2022UdpPacketIdSize + 1 + 8 + 2 + kMinSocks5AddressSize;
    if (datagram_len < kSs2022UdpNonceSize + kMinPlain + SsAeadCipher::kTagSize) {
        return std::nullopt;
    }

    std::array<uint8_t, 24> nonce{};
    std::memcpy(nonce.data(), datagram, nonce.size());
    const uint8_t* ciphertext = datagram + nonce.size();
    const size_t ciphertext_len = datagram_len - nonce.size();

    PlaintextScratch scratch;
    uint8_t* plain_dst = scratch.Prepare(ciphertext_len - SsAeadCipher::kTagSize);
    if (!plain_dst) {
        return std::nullopt;
    }
    for (size_t i = 0; i < users.size(); ++i) {
        const auto& user = users[i];
        if (user.derived_key.size != 32) {
            continue;
        }
        if (!XChaCha20Poly1305Decrypt(
                user.derived_key.span(), nonce,
                std::span<const uint8_t>(ciphertext, ciphertext_len),
                plain_dst)) {
            continue;
        }

        const auto plaintext = scratch.Span();
        std::array<uint8_t, 8> client_session_id{};
        std::memcpy(client_session_id.data(), plaintext.data(), client_session_id.size());
        const uint64_t packet_id = LoadU64BE(
            plaintext.data() + kSs2022UdpSessionIdSize);
        const auto body = plaintext.subspan(
            kSs2022UdpSessionIdSize + kSs2022UdpPacketIdSize);
        auto parsed = Parse2022ClientBodyPlaintext(body, client_session_id);
        if (!parsed) {
            return std::nullopt;
        }
        if (!deferred_replay &&
            !replay_cache.Accept(user.derived_key.span(), client_session_id, packet_id)) {
            return std::nullopt;
        }
        return Make2022DecodeResult(
            i, client_session_id, user.derived_key.span(), packet_id, std::move(*parsed), scratch);
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
    size_t output_size,
    ForwardedMetadataView forwarded) {

    if (key_size > 64 || salt_size > 64 || master_key.size() < key_size ||
        (payload_len > 0 && !payload)) {
        return 0;
    }

    const size_t addr_size = AddressEncodedSize(target, forwarded);
    if (addr_size == 0) {
        return 0;
    }
    const size_t plain_size = addr_size + payload_len;
    const size_t total_size = salt_size + plain_size + SsAeadCipher::kTagSize;
    if (output == nullptr || total_size > output_size) {
        return total_size;
    }

    uint8_t* salt = output;
    uint8_t* ciphertext = output + salt_size;
    if (!WriteClassicUdpPlaintext(target, payload, payload_len,
                                  std::span<uint8_t>(ciphertext, plain_size), forwarded)) {
        return 0;
    }
    if (!RandomBytes(std::span<uint8_t>(salt, salt_size))) {
        return 0;
    }

    std::array<uint8_t, 64> subkey{};
    if (!DeriveSubkey(master_key.data(), key_size,
                      salt, salt_size,
                      subkey.data())) {
        OPENSSL_cleanse(subkey.data(), subkey.size());
        return 0;
    }

    const bool encrypted = AeadEncrypt(
        cipher_type,
        std::span<const uint8_t>(subkey.data(), key_size),
        kZeroNonce,
        std::span<const uint8_t>(ciphertext, plain_size),
        ciphertext);
    OPENSSL_cleanse(subkey.data(), subkey.size());
    if (!encrypted) {
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
    size_t output_size,
    ForwardedMetadataView forwarded = {}) {

    const KeyBytes* body_key = &state.key;
    if (!response && !psk_chain.empty()) {
        body_key = &psk_chain.back();
    }
    if (body_key->empty() || (payload_len > 0 && !payload)) {
        return 0;
    }

    const size_t addr_size = AddressEncodedSize(target, response ? ForwardedMetadataView{} : forwarded);
    if (addr_size == 0) {
        return 0;
    }
    const size_t body_header_size = response ? (1 + 8 + 8 + 2) : (1 + 8 + 2);
    const size_t body_plain_size = body_header_size + addr_size + payload_len;
    const size_t identity_count = response || psk_chain.size() < 2
        ? 0
        : psk_chain.size() - 1;
    const size_t header_bytes =
        kSs2022UdpSeparateHeaderSize +
        identity_count * kSs2022UdpSeparateHeaderSize;
    const size_t total_size =
        header_bytes + body_plain_size + SsAeadCipher::kTagSize;
    if (output == nullptr || total_size > output_size) {
        return total_size;
    }

    uint8_t* body_out = output + header_bytes;
    const bool wrote_body = response
        ? Write2022ServerBodyPlaintext(
              target, payload, payload_len, state.client_session_id,
              std::span<uint8_t>(body_out, body_plain_size))
        : Write2022ClientBodyPlaintext(
              target, payload, payload_len,
              std::span<uint8_t>(body_out, body_plain_size), forwarded);
    if (!wrote_body) {
        return 0;
    }

    std::array<uint8_t, 16> separate{};
    std::memcpy(separate.data(),
                response ? state.server_session_id.data() : state.client_session_id.data(),
                kSs2022UdpSessionIdSize);
    StoreU64BE(separate.data() + kSs2022UdpSessionIdSize, state.next_packet_id);

    const KeyBytes* header_key = response ? &state.key : body_key;
    if (!response && !psk_chain.empty()) {
        header_key = &psk_chain.front();
    }
    if (header_key->empty() ||
        !AesBlocksCrypt<16>(header_key->span(), separate,
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
            const bool encrypted_identity = AesBlocksCrypt<16>(
                psk_chain[i].span(),
                identity_plain,
                std::span<uint8_t, 16>(output + pos, 16),
                true);
            OPENSSL_cleanse(identity_plain.data(), identity_plain.size());
            if (!encrypted_identity) {
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
        OPENSSL_cleanse(subkey.data(), subkey.size());
        return 0;
    }
    std::array<uint8_t, 12> nonce{};
    std::memcpy(nonce.data(), separate.data() + 4, nonce.size());
    const bool encrypted = AeadEncrypt(
        state.cipher_info.type,
        std::span<const uint8_t>(subkey.data(), state.cipher_info.key_size),
        nonce,
        std::span<const uint8_t>(body_out, body_plain_size),
        body_out);
    OPENSSL_cleanse(subkey.data(), subkey.size());
    if (!encrypted) {
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
    size_t output_size,
    ForwardedMetadataView forwarded = {}) {

    if (state.key.size != 32 || (payload_len > 0 && !payload)) {
        return 0;
    }

    const size_t addr_size = AddressEncodedSize(target, response ? ForwardedMetadataView{} : forwarded);
    if (addr_size == 0) {
        return 0;
    }
    const size_t body_header_size = response ? (1 + 8 + 8 + 2) : (1 + 8 + 2);
    const size_t body_plain_size = body_header_size + addr_size + payload_len;
    const size_t plain_size =
        kSs2022UdpSessionIdSize + kSs2022UdpPacketIdSize + body_plain_size;
    const size_t total_size =
        kSs2022UdpNonceSize + plain_size + SsAeadCipher::kTagSize;
    if (output == nullptr || total_size > output_size) {
        return total_size;
    }

    uint8_t* cipher_out = output + kSs2022UdpNonceSize;
    uint8_t* body_out =
        cipher_out + kSs2022UdpSessionIdSize + kSs2022UdpPacketIdSize;
    const bool wrote_body = response
        ? Write2022ServerBodyPlaintext(
              target, payload, payload_len, state.client_session_id,
              std::span<uint8_t>(body_out, body_plain_size))
        : Write2022ClientBodyPlaintext(
              target, payload, payload_len,
              std::span<uint8_t>(body_out, body_plain_size), forwarded);
    if (!wrote_body) {
        return 0;
    }
    std::memcpy(cipher_out,
                response ? state.server_session_id.data() : state.client_session_id.data(),
                kSs2022UdpSessionIdSize);
    StoreU64BE(cipher_out + kSs2022UdpSessionIdSize, state.next_packet_id);

    std::array<uint8_t, 24> nonce{};
    if (!RandomBytes(nonce)) {
        return 0;
    }
    std::memcpy(output, nonce.data(), nonce.size());
    if (!XChaCha20Poly1305Encrypt(
            state.key.span(),
            nonce,
            std::span<const uint8_t>(cipher_out, plain_size),
            cipher_out)) {
        return 0;
    }

    ++state.next_packet_id;
    return total_size;
}

}  // namespace

bool Ss2022UdpReplayWindow::Accept(uint64_t packet_id) noexcept {
    if (!initialized_) {
        initialized_ = true;
        highest_ = packet_id;
        seen_[0] = 1;
        return true;
    }

    if (packet_id > highest_) {
        const uint64_t distance = packet_id - highest_;
        Advance(distance >= kWindowBits
                    ? kWindowBits
                    : static_cast<size_t>(distance));
        highest_ = packet_id;
        seen_[0] |= 1;
        return true;
    }

    const uint64_t distance = highest_ - packet_id;
    if (distance >= kWindowBits) {
        return false;
    }
    const size_t word = static_cast<size_t>(distance / kWordBits);
    const uint64_t mask = uint64_t{1} << (distance % kWordBits);
    if ((seen_[word] & mask) != 0) {
        return false;
    }
    seen_[word] |= mask;
    return true;
}

void Ss2022UdpReplayWindow::Advance(size_t distance) noexcept {
    if (distance >= kWindowBits) {
        seen_.fill(0);
        return;
    }

    const size_t word_shift = distance / kWordBits;
    const size_t bit_shift = distance % kWordBits;
    for (size_t dst = kWordCount; dst-- > 0;) {
        uint64_t value = 0;
        if (dst >= word_shift) {
            value = seen_[dst - word_shift] << bit_shift;
            if (bit_shift != 0 && dst > word_shift) {
                value |= seen_[dst - word_shift - 1] >>
                    (kWordBits - bit_shift);
            }
        }
        seen_[dst] = value;
    }
}

size_t Ss2022UdpReplayCache::SessionKeyHash::operator()(
    const SessionKey& key) const noexcept {
    static const std::array<uint64_t, 2> kSeed = [] {
        std::array<uint64_t, 2> seed{};
        (void)RAND_bytes(reinterpret_cast<uint8_t*>(seed.data()), sizeof(seed));
        return seed;
    }();
    std::array<uint8_t, KeyBytes::kMaxSize + 1 + sizeof(uint64_t)> buf{};
    const size_t cred_len = std::min(key.credential.size, KeyBytes::kMaxSize);
    std::memcpy(buf.data(), key.credential.bytes.data(), cred_len);
    buf[cred_len] = static_cast<uint8_t>(cred_len);
    StoreU64BE(buf.data() + cred_len + 1, key.session_id);
    const size_t hash = static_cast<size_t>(
        SIPHASH_24(kSeed.data(), buf.data(), cred_len + 1 + sizeof(uint64_t)));
    OPENSSL_cleanse(buf.data(), cred_len);
    return hash;
}

bool Ss2022UdpReplayCache::Accept(
    std::span<const uint8_t> authenticated_key,
    std::span<const uint8_t, 8> session_id,
    uint64_t packet_id,
    std::chrono::steady_clock::time_point now) {
    SessionKey key;
    if (authenticated_key.empty() || !key.credential.assign(authenticated_key)) return false;
    key.session_id = LoadU64BE(session_id.data());
    auto it = sessions_.find(key);
    if (it != sessions_.end()) {
        if (now - it->second.last_seen < kRetention) {
            if (!it->second.window.Accept(packet_id)) {
                return false;
            }
            it->second.last_seen = now;
            return true;
        }
        sessions_.erase(it);
    }

    if (sessions_.size() >= kMaxSessions) {
        PruneExpired(now);
        if (sessions_.size() >= kMaxSessions) {
            return false;
        }
    }

    Session session;
    session.last_seen = now;
    if (!session.window.Accept(packet_id)) {
        return false;
    }
    sessions_.emplace(key, std::move(session));
    return true;
}

void Ss2022UdpReplayCache::PruneExpired(
    std::chrono::steady_clock::time_point now) {
    for (auto it = sessions_.begin(); it != sessions_.end();) {
        if (now - it->second.last_seen >= kRetention) {
            it = sessions_.erase(it);
        } else {
            ++it;
        }
    }
    MaybeShrinkHashContainer(sessions_);
}

const InboundDatagramAssociationPolicy& Ss2022UdpAssociation::Policy() noexcept {
    static const InboundDatagramAssociationPolicy policy{
        Ss2022UdpReplayCache::kMaxSessions,
        Ss2022UdpReplayCache::kRetention,
        []() -> std::unique_ptr<InboundDatagramAssociation> {
            return std::make_unique<Ss2022UdpAssociation>();
        }};
    return policy;
}

bool Ss2022UdpAssociation::Check(
    uint64_t packet_id, uint32_t worker, const udp::endpoint& endpoint,
    InboundDatagramCheck check, Clock::time_point now) noexcept {
    // SIP022 permits unseen in-window reordering. A path change additionally
    // requires a newer authenticated packet, preventing an old source from
    // reclaiming either execution ownership or the reply endpoint.
    if (path_packet_id_ && packet_id <= *path_packet_id_ &&
        (worker != path_worker_ || endpoint != path_endpoint_)) return false;
    if (check == InboundDatagramCheck::Inspect) {
        auto candidate = replay_;
        return candidate.Accept(packet_id);
    }
    if (!replay_.Accept(packet_id)) return false;
    if (!path_packet_id_ || packet_id > *path_packet_id_) path_packet_id_ = packet_id;
    path_worker_ = worker;
    path_endpoint_ = endpoint;
    ProtectUntil(now + Policy().retention);
    return true;
}

std::optional<SsUdpDecodeResult> DecodeUdpPacket(
    const uint8_t* datagram,
    size_t datagram_len,
    const proxyman::inbound::UserStore::ShadowsocksUsersView& users,
    SsCipherType cipher_type,
    size_t key_size,
    size_t salt_size,
    Ss2022UdpReplayCache& replay_cache,
    bool deferred_replay) {

    if (users.empty()) {
        return std::nullopt;
    }

    const SsCipherInfo cipher_info{cipher_type, key_size, salt_size};
    if (Is2022AesCipher(cipher_type)) {
        return Decode2022UdpAesRequest(
            datagram, datagram_len, users, cipher_info, replay_cache, deferred_replay);
    }
    if (cipher_type == SsCipherType::CHACHA20_POLY1305_2022) {
        return Decode2022UdpChachaRequest(
            datagram, datagram_len, users, replay_cache, deferred_replay);
    }

    if (key_size > 64 || salt_size > 64) {
        return std::nullopt;
    }

    if (datagram_len < salt_size + SsAeadCipher::kTagSize + kMinSocks5AddressSize) {
        return std::nullopt;
    }

    const uint8_t* salt = datagram;
    const uint8_t* cipher = datagram + salt_size;
    const size_t cipherlen = datagram_len - salt_size;
    const size_t plaintext_len = cipherlen - SsAeadCipher::kTagSize;
    PlaintextScratch scratch;
    uint8_t* plain_dst = scratch.Prepare(plaintext_len);
    if (!plain_dst) {
        return std::nullopt;
    }

    for (size_t i = 0; i < users.size(); ++i) {
        const auto& user = users[i];

        std::array<uint8_t, 64> subkey{};
        if (!DeriveSubkey(user.derived_key.data(), key_size,
                          salt, salt_size,
                          subkey.data())) {
            OPENSSL_cleanse(subkey.data(), subkey.size());
            continue;
        }

        const bool decrypted = AeadDecrypt(
            cipher_type,
            std::span<const uint8_t>(subkey.data(), key_size),
            kZeroNonce,
            std::span<const uint8_t>(cipher, cipherlen),
            plain_dst);
        OPENSSL_cleanse(subkey.data(), subkey.size());
        if (!decrypted) {
            continue;
        }
        auto addr = DecodeAddress(
            scratch.Span(),
            AddressWireFormat::Socks5,
            {.require_non_empty_domain = true, .allow_metadata = true});
        if (addr.status != AddressDecodeStatus::Complete || !addr.target.IsValid()) {
            return std::nullopt;
        }

        SsUdpDecodeResult result;
        result.target = std::move(addr.target);
        result.forwarded = std::move(addr.forwarded);
        result.user_index = i;

        const size_t payload_offset = std::min(addr.consumed, plaintext_len);
        if (!scratch.MoveSuffixTo(payload_offset, result.payload) ||
            !buf::SetUdpTarget(result.payload, result.target)) {
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
    size_t output_size,
    ForwardedMetadataView forwarded) {

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
        output_size,
        forwarded);
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
    if (datagram_len < salt_size + SsAeadCipher::kTagSize + kMinSocks5AddressSize) {
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
        OPENSSL_cleanse(subkey.data(), subkey.size());
        return std::nullopt;
    }

    PlaintextScratch scratch;
    uint8_t* plain_dst = scratch.Prepare(plaintext_len);
    if (!plain_dst) {
        OPENSSL_cleanse(subkey.data(), subkey.size());
        return std::nullopt;
    }
    const bool decrypted = AeadDecrypt(
        cipher_type,
        std::span<const uint8_t>(subkey.data(), key_size),
        kZeroNonce,
        std::span<const uint8_t>(cipher, cipherlen),
        plain_dst);
    OPENSSL_cleanse(subkey.data(), subkey.size());
    if (!decrypted) {
        return std::nullopt;
    }

    auto addr = DecodeAddress(
        scratch.Span(),
        AddressWireFormat::Socks5,
        {.require_non_empty_domain = true, .allow_metadata = false});
    if (addr.status != AddressDecodeStatus::Complete || !addr.target.IsValid()) {
        return std::nullopt;
    }

    SsUdpDecodeResult result;
    result.target = std::move(addr.target);

    const size_t payload_offset = std::min(addr.consumed, plaintext_len);
    if (!scratch.MoveSuffixTo(payload_offset, result.payload) ||
        !buf::SetUdpTarget(result.payload, result.target)) {
        return std::nullopt;
    }
    return result;
}

bool Init2022UdpSessionState(
    Ss2022UdpSessionState& state,
    const SsCipherInfo& cipher_info,
    const KeyBytes& key) {

    if (!Is2022Cipher(cipher_info.type) || key.empty()) {
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
    size_t output_size,
    ForwardedMetadataView forwarded) {

    if (Is2022AesCipher(state.cipher_info.type)) {
        return Encode2022UdpAesPacketTo(
            target, payload, payload_len, state, psk_chain,
            false, output, output_size, forwarded);
    }
    if (state.cipher_info.type == SsCipherType::CHACHA20_POLY1305_2022) {
        return Encode2022UdpChachaPacketTo(
            target, payload, payload_len, state, false, output, output_size, forwarded);
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

    if (!Is2022Cipher(state.cipher_info.type) || state.key.empty()) {
        return std::nullopt;
    }

    PlaintextScratch scratch;
    std::span<const uint8_t> body_span;
    std::array<uint8_t, kSs2022UdpSessionIdSize> server_session_id{};
    uint64_t packet_id = 0;
    if (Is2022AesCipher(state.cipher_info.type)) {
        constexpr size_t kMinBodyPlain = 1 + 8 + 8 + 2 + kMinSocks5AddressSize;
        if (datagram_len < kSs2022UdpSeparateHeaderSize +
                kMinBodyPlain + SsAeadCipher::kTagSize) {
            return std::nullopt;
        }
        std::array<uint8_t, 16> encrypted_separate{};
        std::memcpy(encrypted_separate.data(), datagram, encrypted_separate.size());
        std::array<uint8_t, 16> separate{};
        if (!AesBlocksCrypt<16>(state.key.span(), encrypted_separate, separate, false)) {
            return std::nullopt;
        }
        std::memcpy(
            server_session_id.data(), separate.data(), server_session_id.size());
        packet_id = LoadU64BE(separate.data() + kSs2022UdpSessionIdSize);
        const size_t body_offset = kSs2022UdpSeparateHeaderSize;
        const size_t ciphertext_len = datagram_len - body_offset;
        uint8_t* plain_dst = scratch.Prepare(ciphertext_len - SsAeadCipher::kTagSize);
        if (!plain_dst) {
            return std::nullopt;
        }

        std::array<uint8_t, 32> subkey{};
        if (!Derive2022Subkey(state.key.data(), state.key.size,
                              separate.data(), kSs2022UdpSessionIdSize,
                              subkey.data())) {
            OPENSSL_cleanse(subkey.data(), subkey.size());
            return std::nullopt;
        }
        std::array<uint8_t, 12> nonce{};
        std::memcpy(nonce.data(), separate.data() + 4, nonce.size());
        const bool decrypted = AeadDecrypt(
            state.cipher_info.type,
            std::span<const uint8_t>(subkey.data(), state.cipher_info.key_size),
            nonce,
            std::span<const uint8_t>(datagram + body_offset, ciphertext_len),
            plain_dst);
        OPENSSL_cleanse(subkey.data(), subkey.size());
        if (!decrypted) {
            return std::nullopt;
        }
        body_span = scratch.Span();
    } else if (state.cipher_info.type == SsCipherType::CHACHA20_POLY1305_2022) {
        constexpr size_t kMinPlain =
            kSs2022UdpSessionIdSize + kSs2022UdpPacketIdSize + 1 + 8 + 8 + 2 + kMinSocks5AddressSize;
        if (datagram_len < kSs2022UdpNonceSize + kMinPlain + SsAeadCipher::kTagSize) {
            return std::nullopt;
        }
        std::array<uint8_t, 24> nonce{};
        std::memcpy(nonce.data(), datagram, nonce.size());
        const uint8_t* ciphertext = datagram + nonce.size();
        const size_t ciphertext_len = datagram_len - nonce.size();
        uint8_t* plain_dst = scratch.Prepare(ciphertext_len - SsAeadCipher::kTagSize);
        if (!plain_dst) {
            return std::nullopt;
        }
        if (!XChaCha20Poly1305Decrypt(
                state.key.span(), nonce,
                std::span<const uint8_t>(ciphertext, ciphertext_len),
                plain_dst)) {
            return std::nullopt;
        }
        const auto plaintext = scratch.Span();
        std::memcpy(
            server_session_id.data(), plaintext.data(), server_session_id.size());
        packet_id = LoadU64BE(
            plaintext.data() + kSs2022UdpSessionIdSize);
        body_span = plaintext.subspan(
            kSs2022UdpSessionIdSize + kSs2022UdpPacketIdSize);
    } else {
        return std::nullopt;
    }

    auto parsed = Parse2022ServerBodyPlaintext(body_span, state.client_session_id);
    if (!parsed) {
        return std::nullopt;
    }
    if (!state.receive_replay_cache.Accept(state.key.span(), server_session_id, packet_id)) {
        return std::nullopt;
    }

    SsUdpDecodeResult result;
    result.target = std::move(parsed->target);
    const size_t payload_offset = static_cast<size_t>(
        parsed->payload.data() - scratch.Span().data());
    if (!scratch.MoveSuffixTo(payload_offset, result.payload) ||
        !buf::SetUdpTarget(result.payload, result.target)) {
        return std::nullopt;
    }
    return result;
}

}  // namespace ss
