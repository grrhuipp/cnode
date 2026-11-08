#include "sniff/sniffer.hpp"
#include "common/allocator.hpp"
#include "common/byte_reader.hpp"
#include "core/constants.hpp"

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <bit>
#include <span>
#include <string_view>

namespace {

struct QuicVersion {
    uint32_t ver = 0;
    uint8_t type_initial = 0;
    std::array<uint8_t, 20> salt{};
    std::string_view hp_label;
    std::string_view key_label;
    std::string_view iv_label;
};

constexpr QuicVersion kDraft29{
    0xff00001d,
    0,
    {0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97,
     0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0, 0x43, 0x90, 0xa8, 0x99},
    "quic hp",
    "quic key",
    "quic iv",
};
constexpr QuicVersion kV1{
    0x1,
    0,
    {0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
     0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a},
    "quic hp",
    "quic key",
    "quic iv",
};
constexpr QuicVersion kV2{
    0x6b3343cf,
    1,
    {0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93,
     0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9},
    "quicv2 hp",
    "quicv2 key",
    "quicv2 iv",
};

[[nodiscard]] const QuicVersion* LookupVersion(uint32_t ver) noexcept {
    if (ver == kV1.ver) return &kV1;
    if (ver == kV2.ver) return &kV2;
    if (ver == kDraft29.ver) return &kDraft29;
    return nullptr;
}

[[nodiscard]] bool ReadVarint(std::span<const uint8_t> data,
                              size_t& offset,
                              uint64_t& value) noexcept {
    if (offset >= data.size()) return false;
    const uint8_t first = data[offset];
    const size_t length = static_cast<size_t>(1u) << (first >> 6);
    if (offset + length > data.size()) return false;
    value = first & 0x3f;
    for (size_t i = 1; i < length; ++i) {
        value = (value << 8) | data[offset + i];
    }
    offset += length;
    return true;
}

bool HkdfExtract(std::span<const uint8_t> salt,
                 std::span<const uint8_t> ikm,
                 std::array<uint8_t, 32>& out) noexcept {
    unsigned int out_len = 0;
    return HMAC(EVP_sha256(), salt.data(), static_cast<int>(salt.size()),
                ikm.data(), ikm.size(), out.data(), &out_len) != nullptr &&
           out_len == out.size();
}

// TLS 1.3 HKDF-Expand-Label with SHA-256 for L <= 32 (single HMAC block T(1)).
bool HkdfExpandLabel(std::span<const uint8_t> secret,
                     std::string_view label,
                     std::span<uint8_t> out) noexcept {
    if (out.empty() || out.size() > 32 || label.size() > 16) {
        return false;
    }
    std::array<uint8_t, 2 + 1 + 6 + 16 + 1 + 1> info_buf{};
    const auto label_size = static_cast<uint8_t>(6 + label.size());
    info_buf[0] = static_cast<uint8_t>((out.size() >> 8) & 0xff);
    info_buf[1] = static_cast<uint8_t>(out.size() & 0xff);
    info_buf[2] = label_size;
    std::memcpy(info_buf.data() + 3, "tls13 ", 6);
    std::memcpy(info_buf.data() + 9, label.data(), label.size());
    const size_t info_len = 3 + static_cast<size_t>(label_size) + 1;
    info_buf[info_len] = 0x01;

    std::array<uint8_t, 32> digest{};
    unsigned int digest_len = 0;
    if (HMAC(EVP_sha256(),
             secret.data(),
             static_cast<int>(secret.size()),
             info_buf.data(),
             info_len + 1,
             digest.data(),
             &digest_len) == nullptr ||
        digest_len != digest.size()) {
        return false;
    }
    std::memcpy(out.data(), digest.data(), out.size());
    return true;
}

EVP_CIPHER_CTX* ThreadLocalQuicCipherCtx() noexcept {
    struct Holder {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        ~Holder() {
            if (ctx) EVP_CIPHER_CTX_free(ctx);
        }
    };
    thread_local Holder holder;
    if (holder.ctx) {
        EVP_CIPHER_CTX_reset(holder.ctx);
    }
    return holder.ctx;
}

bool AesEcbEncrypt(std::span<const uint8_t, 16> key,
                   std::span<const uint8_t, 16> in,
                   std::span<uint8_t, 16> out) noexcept {
    EVP_CIPHER_CTX* ctx = ThreadLocalQuicCipherCtx();
    if (!ctx) return false;
    int out_len = 0;
    return EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, key.data(), nullptr) == 1 &&
           EVP_CIPHER_CTX_set_padding(ctx, 0) == 1 &&
           EVP_EncryptUpdate(ctx, out.data(), &out_len, in.data(), 16) == 1 &&
           out_len == 16;
}

constexpr size_t kMaxCrypto = 64 * 1024;
constexpr size_t kMaxInputs = 64;

// Explicit reservation prevents vector's geometric growth from exceeding the cap.
void Grow(memory::ByteVector& bytes, size_t size) {
    if (size > bytes.capacity()) {
        bytes.reserve(std::bit_ceil(std::max(size, size_t{256})));
    }
    bytes.resize(size);
}

bool AesGcmDecrypt(std::span<const uint8_t, 16> key,
                   std::span<const uint8_t, 12> nonce,
                   uint8_t unmasked_first_byte,
                   std::span<const uint8_t> aad_middle,
                   std::span<const uint8_t> unmasked_pn,
                   std::span<const uint8_t> ciphertext,
                   memory::ByteVector& plaintext) {
    if (ciphertext.size() <= 16) return false; // A QUIC packet must contain a frame.
    const auto tag = ciphertext.subspan(ciphertext.size() - 16, 16);
    const auto body = ciphertext.first(ciphertext.size() - 16);
    plaintext.resize(body.size());

    EVP_CIPHER_CTX* ctx = ThreadLocalQuicCipherCtx();
    if (!ctx) return false;
    int aad_len = 0;
    int out_len = 0;
    int final_len = 0;
    const bool ok =
        EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) == 1 &&
        EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) == 1 &&
        EVP_DecryptUpdate(ctx, nullptr, &aad_len, &unmasked_first_byte, 1) == 1 &&
        EVP_DecryptUpdate(ctx, nullptr, &aad_len, aad_middle.data(),
                          static_cast<int>(aad_middle.size())) == 1 &&
        EVP_DecryptUpdate(ctx, nullptr, &aad_len, unmasked_pn.data(),
                          static_cast<int>(unmasked_pn.size())) == 1 &&
        EVP_DecryptUpdate(ctx, plaintext.data(), &out_len, body.data(),
                          static_cast<int>(body.size())) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16,
                            const_cast<uint8_t*>(tag.data())) == 1 &&
        EVP_DecryptFinal_ex(ctx, plaintext.data() + out_len, &final_len) == 1;
    if (!ok) {
        plaintext.clear();
        return false;
    }
    plaintext.resize(static_cast<size_t>(out_len + final_len));
    return true;
}

}  // namespace

SniffResult QuicSniffer::Sniff(std::span<const uint8_t> data) {
    auto fail = [&]() {
        stopped_ = true;
        crypto_.clear();
        crypto_.shrink_to_fit();
        coverage_.clear();
        coverage_.shrink_to_fit();
        return SniffResult{};
    };
    if (stopped_) return {};
    // As in the read budget, consume one final datagram crossing the threshold.
    // Every individual buffer stays <=64 KiB and total input stays <128 KiB.
    if (data.empty() || input_count_ == kMaxInputs || data.size() > kMaxCrypto ||
        input_bytes_ >= kMaxCrypto) {
        return fail();
    }
    ++input_count_;
    input_bytes_ += data.size();

    // Released on return: no plaintext is held while waiting for the next datagram.
    memory::ByteVector decrypted;
    size_t offset = 0;
    bool decrypted_initial = false;
    bool valid_long_packet = false;
    uint32_t datagram_version = version_;
    std::span<const uint8_t> datagram_dcid(dcid_.data(), dcid_size_);
    while (offset < data.size()) {
        const auto remaining = data.subspan(offset);
        // A coalesced short-header packet or datagram padding has no Initial
        // length to follow. Do not discard CRYPTO already authenticated here.
        if ((remaining[0] & 0xc0) != 0xc0) {
            if (decrypted_initial || valid_long_packet) break;
            return fail();
        }
        if (remaining.size() < 7) return fail();
        const uint32_t version = ByteReader(remaining.subspan(1, 4)).ReadU32BE();
        const auto* spec = LookupVersion(version);
        if (!spec) return fail();
        const uint8_t packet_type = (remaining[0] >> 4) & 3;
        const bool is_initial = packet_type == spec->type_initial;
        // Retry has no Length field and cannot contribute to this Initial.
        if (packet_type == (version == kV2.ver ? 0 : 3)) {
            if (decrypted_initial || valid_long_packet) break;
            return fail();
        }

        size_t cursor = 5;
        const uint8_t dcid_len = remaining[cursor++];
        if (dcid_len > dcid_.size() || dcid_len > remaining.size() - cursor)
            return fail();
        const auto dcid = remaining.subspan(cursor, dcid_len);
        cursor += dcid_len;
        if (cursor == remaining.size()) return fail();
        const uint8_t scid_len = remaining[cursor++];
        if (scid_len > 20 || scid_len > remaining.size() - cursor) return fail();
        cursor += scid_len;
        if (is_initial) {
            uint64_t token_len = 0;
            if (!ReadVarint(remaining, cursor, token_len) ||
                token_len > remaining.size() - cursor) return fail();
            cursor += static_cast<size_t>(token_len);
        }
        uint64_t packet_len = 0;
        if (!ReadVarint(remaining, cursor, packet_len) ||
            packet_len > remaining.size() - cursor) return fail();
        const size_t hdr_len = cursor;
        const size_t next_offset = offset + hdr_len + static_cast<size_t>(packet_len);
        // Protected packet numbers and tags require at least this much space
        // for a header-protection sample, even when the payload is opaque.
        if (packet_len < 20) return fail();
        if (datagram_version != 0 &&
            (version != datagram_version || dcid.size() != datagram_dcid.size() ||
             !std::equal(dcid.begin(), dcid.end(), datagram_dcid.begin()))) return fail();
        datagram_version = version;
        datagram_dcid = dcid;
        if (!is_initial) {
            valid_long_packet = true;
            offset = next_offset;
            continue;
        }
        if (version_ == 0) {
            std::array<uint8_t, 32> initial_secret{};
            std::array<uint8_t, 32> client_secret{};
            if (!HkdfExtract(spec->salt, dcid, initial_secret) ||
                !HkdfExpandLabel(initial_secret, "client in", client_secret) ||
                !HkdfExpandLabel(client_secret, spec->hp_label, hp_key_) ||
                !HkdfExpandLabel(client_secret, spec->key_label, key_) ||
                !HkdfExpandLabel(client_secret, spec->iv_label, iv_)) return fail();
        }

        std::array<uint8_t, 16> mask{};
        const std::span<const uint8_t, 16> sample(remaining.data() + hdr_len + 4, 16);
        if (!AesEcbEncrypt(hp_key_, sample, mask)) return fail();
        const uint8_t first = static_cast<uint8_t>(remaining[0] ^ (mask[0] & 0x0f));
        if ((first & 0x0c) != 0) return fail();
        const size_t pn_len = (first & 3) + 1;
        std::array<uint8_t, 4> pn_bytes{};
        uint64_t packet_number = 0;
        for (size_t i = 0; i < pn_len; ++i) {
            pn_bytes[i] = remaining[hdr_len + i] ^ mask[i + 1];
            packet_number = (packet_number << 8) | pn_bytes[i];
        }
        // RFC 9000 Appendix A.3: truncated packet numbers may wrap even in
        // Initial retransmissions; reordered packets use the same number space.
        const uint64_t expected = version_ == 0 ? 0 : largest_pn_ + 1;
        const uint64_t window = uint64_t{1} << (pn_len * 8);
        const uint64_t half_window = window / 2;
        packet_number |= expected & ~(window - 1);
        if (packet_number + half_window <= expected &&
            packet_number < (uint64_t{1} << 62) - window) {
            packet_number += window;
        } else if (packet_number > expected + half_window && packet_number >= window) {
            packet_number -= window;
        }
        auto nonce = iv_;
        for (size_t i = 0; i < 8; ++i)
            nonce[nonce.size() - 1 - i] ^= static_cast<uint8_t>(packet_number >> (8 * i));
        if (!AesGcmDecrypt(key_, nonce, first, remaining.subspan(1, hdr_len - 1),
                std::span<const uint8_t>(pn_bytes.data(), pn_len),
                remaining.subspan(hdr_len + pn_len,
                                  static_cast<size_t>(packet_len) - pn_len),
                decrypted)) return fail();
        if (version_ == 0) {
            version_ = version;
            dcid_size_ = dcid_len;
            std::copy(dcid.begin(), dcid.end(), dcid_.begin());
        }
        largest_pn_ = std::max(largest_pn_, packet_number);
        decrypted_initial = true;

        const auto plaintext = std::span<const uint8_t>(decrypted);
        size_t frame = 0;
        while (frame < plaintext.size()) {
            uint64_t frame_type = 0;
            if (!ReadVarint(plaintext, frame, frame_type)) return fail();
            auto consume = [&](uint64_t& value) {
                return ReadVarint(plaintext, frame, value);
            };
            switch (frame_type) {
                case 0x00: // PADDING
                case 0x01: // PING
                    break;
                case 0x02:
                case 0x03: {
                    uint64_t ignored = 0;
                    uint64_t ranges = 0;
                    if (!consume(ignored) || !consume(ignored) ||
                        !consume(ranges) || !consume(ignored) ||
                        ranges > (plaintext.size() - frame) / 2) return fail();
                    for (uint64_t i = 0; i < ranges; ++i)
                        if (!consume(ignored) || !consume(ignored)) return fail();
                    if (frame_type == 0x03 &&
                        (!consume(ignored) || !consume(ignored) || !consume(ignored)))
                        return fail();
                    break;
                }
                case 0x06: {
                    uint64_t start = 0;
                    uint64_t length = 0;
                    if (!consume(start) || !consume(length) ||
                        start > kMaxCrypto || length > kMaxCrypto - start ||
                        length > plaintext.size() - frame) return fail();
                    if (length == 0) break;
                    const size_t end = static_cast<size_t>(start + length);
                    if (contiguous_ >= 4 &&
                        end > 4 + ((static_cast<size_t>(crypto_[1]) << 16) |
                                   (static_cast<size_t>(crypto_[2]) << 8) | crypto_[3])) {
                        return fail();
                    }
                    if (crypto_.size() < end) {
                        Grow(crypto_, end);
                        Grow(coverage_, (end + 7) / 8);
                    }
                    for (size_t i = static_cast<size_t>(start); i < end; ++i) {
                        const uint8_t bit = static_cast<uint8_t>(1u << (i & 7));
                        const uint8_t byte = plaintext[frame++];
                        if ((coverage_[i / 8] & bit) != 0) {
                            if (crypto_[i] != byte) return fail();
                        } else {
                            crypto_[i] = byte;
                            coverage_[i / 8] |= bit;
                        }
                    }
                    while (contiguous_ < crypto_.size() &&
                           (coverage_[contiguous_ / 8] & (1u << (contiguous_ & 7))) != 0)
                        ++contiguous_;
                    break;
                }
                // CONNECTION_CLOSE and unsupported Initial frames are terminal.
                default:
                    return fail();
            }
        }

        if (contiguous_ != 0 && crypto_[0] != 1) return fail();
        if (contiguous_ >= 4) {
            const size_t handshake_size =
                (static_cast<size_t>(crypto_[1]) << 16) |
                (static_cast<size_t>(crypto_[2]) << 8) | crypto_[3];
            if (handshake_size > kMaxCrypto - 4 ||
                crypto_.size() > handshake_size + 4) return fail();
            if (contiguous_ >= handshake_size + 4) {
                auto sni = ParseClientHelloServerName(
                    std::span<const uint8_t>(crypto_).first(handshake_size + 4));
                if (!sni) return fail();
                SniffResult result;
                result.success = true;
                result.protocol = constants::protocol::kQuic;
                result.domain.assign(*sni);
                stopped_ = true;
                crypto_.clear();
                crypto_.shrink_to_fit();
                coverage_.clear();
                coverage_.shrink_to_fit();
                return result;
            }
        }
        offset = next_offset;
    }
    // A same-connection 0-RTT-only datagram may be reordered between Initial
    // fragments. It contributes no CRYPTO, but does not invalidate prior state.
    if (version_ == 0 || input_count_ == kMaxInputs || input_bytes_ >= kMaxCrypto)
        return fail();
    SniffResult result;
    result.need_more = true;
    result.protocol = constants::protocol::kQuic;
    return result;
}

