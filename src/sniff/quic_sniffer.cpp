#include "acppnode/sniff/sniffer.hpp"
#include "acppnode/core/constants.hpp"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace acpp {
namespace {

struct QuicVersion {
    uint32_t ver = 0;
    uint8_t type_initial = 0;
    std::array<uint8_t, 20> salt{};
    std::string_view label_prefix;
};

constexpr QuicVersion kDraft29{
    0xff00001d,
    0,
    {0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97,
     0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0, 0x43, 0x90, 0xa8, 0x99},
    "quic",
};
constexpr QuicVersion kV1{
    0x1,
    0,
    {0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
     0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a},
    "quic",
};
constexpr QuicVersion kV2{
    0x6b3343cf,
    1,
    {0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93,
     0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9},
    "quicv2",
};

[[nodiscard]] const QuicVersion* LookupVersion(uint32_t ver) noexcept {
    if (ver == kV1.ver) return &kV1;
    if (ver == kV2.ver) return &kV2;
    if (ver == kDraft29.ver) return &kDraft29;
    return nullptr;
}

[[nodiscard]] uint32_t ReadU32(std::span<const uint8_t> data, size_t offset) noexcept {
    return (static_cast<uint32_t>(data[offset]) << 24) |
           (static_cast<uint32_t>(data[offset + 1]) << 16) |
           (static_cast<uint32_t>(data[offset + 2]) << 8) |
           static_cast<uint32_t>(data[offset + 3]);
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
    if (value > 65535) return false;
    offset += length;
    return true;
}

bool HkdfExtract(std::span<const uint8_t> salt,
                 std::span<const uint8_t> ikm,
                 std::array<uint8_t, 32>& out) {
    unsigned int out_len = 0;
    return HMAC(EVP_sha256(), salt.data(), static_cast<int>(salt.size()),
                ikm.data(), ikm.size(), out.data(), &out_len) != nullptr &&
           out_len == out.size();
}

bool HkdfExpandLabel(std::span<const uint8_t> secret,
                     std::string_view label,
                     std::span<uint8_t> out) {
    std::array<uint8_t, 2 + 1 + 6 + 16 + 1> info_buf{};
    const auto label_size = static_cast<uint8_t>(6 + label.size());
    if (label.size() > 16 ||
        2 + 1 + label_size + 1 > info_buf.size()) {
        return false;
    }
    info_buf[0] = static_cast<uint8_t>((out.size() >> 8) & 0xff);
    info_buf[1] = static_cast<uint8_t>(out.size() & 0xff);
    info_buf[2] = label_size;
    std::memcpy(info_buf.data() + 3, "tls13 ", 6);
    std::memcpy(info_buf.data() + 9, label.data(), label.size());
    const size_t info_len = 3 + label_size + 1;

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (!ctx) return false;
    bool ok = EVP_PKEY_derive_init(ctx) == 1 &&
              EVP_PKEY_CTX_hkdf_mode(ctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY) == 1 &&
              EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) == 1 &&
              EVP_PKEY_CTX_set1_hkdf_key(ctx, secret.data(),
                                         static_cast<int>(secret.size())) == 1 &&
              EVP_PKEY_CTX_add1_hkdf_info(ctx, info_buf.data(),
                                          static_cast<int>(info_len)) == 1;
    size_t out_len = out.size();
    ok = ok && EVP_PKEY_derive(ctx, out.data(), &out_len) == 1 &&
         out_len == out.size();
    EVP_PKEY_CTX_free(ctx);
    return ok;
}

bool AesEcbEncrypt(std::span<const uint8_t, 16> key,
                   std::span<const uint8_t, 16> in,
                   std::span<uint8_t, 16> out) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    int out_len = 0;
    const bool ok =
        EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, key.data(), nullptr) == 1 &&
        EVP_CIPHER_CTX_set_padding(ctx, 0) == 1 &&
        EVP_EncryptUpdate(ctx, out.data(), &out_len, in.data(), 16) == 1 &&
        out_len == 16;
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

bool AesGcmDecrypt(std::span<const uint8_t, 16> key,
                   std::span<const uint8_t, 12> nonce,
                   std::span<const uint8_t> aad,
                   std::span<const uint8_t> ciphertext,
                   std::vector<uint8_t>& plaintext) {
    if (ciphertext.size() < 16) return false;
    const auto tag = ciphertext.subspan(ciphertext.size() - 16, 16);
    const auto body = ciphertext.first(ciphertext.size() - 16);
    plaintext.resize(body.size());

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    int out_len = 0;
    int final_len = 0;
    bool ok = EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr) == 1 &&
              EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) == 1 &&
              EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) == 1 &&
              EVP_DecryptUpdate(ctx, nullptr, &out_len, aad.data(),
                                static_cast<int>(aad.size())) == 1 &&
              EVP_DecryptUpdate(ctx, plaintext.data(), &out_len, body.data(),
                                static_cast<int>(body.size())) == 1 &&
              EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16,
                                  const_cast<uint8_t*>(tag.data())) == 1 &&
              EVP_DecryptFinal_ex(ctx, plaintext.data() + out_len, &final_len) == 1;
    EVP_CIPHER_CTX_free(ctx);
    if (!ok) {
        plaintext.clear();
        return false;
    }
    plaintext.resize(static_cast<size_t>(out_len + final_len));
    return true;
}

}  // namespace

SniffResult QuicSniffer::Sniff(std::span<const uint8_t> data) {
    SniffResult result;
    if (data.empty()) return result;

    std::vector<uint8_t> packet(data.begin(), data.end());
    std::vector<uint8_t> crypto;
    crypto.resize(0);

    size_t offset = 0;
    while (offset < packet.size()) {
        auto remaining = std::span<uint8_t>(packet).subspan(offset);
        if (remaining.size() < 6) break;
        uint8_t type_byte = remaining[0];
        if ((type_byte & 0x80) == 0 || (type_byte & 0x40) == 0) {
            return result;
        }
        const uint32_t version = ReadU32(remaining, 1);
        const auto* spec = LookupVersion(version);
        if (!spec) return result;

        size_t cursor = 5;
        if (cursor >= remaining.size()) return result;
        const uint8_t dcid_len = remaining[cursor++];
        if (cursor + dcid_len > remaining.size()) return result;
        const auto dcid = remaining.subspan(cursor, dcid_len);
        cursor += dcid_len;
        if (cursor >= remaining.size()) return result;
        const uint8_t scid_len = remaining[cursor++];
        if (cursor + scid_len > remaining.size()) return result;
        cursor += scid_len;

        const uint8_t packet_type = (type_byte & 0x30) >> 4;
        const bool is_initial = packet_type == spec->type_initial;
        if (is_initial) {
            uint64_t token_len = 0;
            if (!ReadVarint(remaining, cursor, token_len) ||
                cursor + static_cast<size_t>(token_len) > remaining.size()) {
                return result;
            }
            cursor += static_cast<size_t>(token_len);
        }

        uint64_t packet_len = 0;
        if (!ReadVarint(remaining, cursor, packet_len) || packet_len < 4) {
            return result;
        }
        const size_t hdr_len = cursor;
        if (remaining.size() < hdr_len + static_cast<size_t>(packet_len)) {
            return result;
        }
        const size_t next_offset = offset + hdr_len + static_cast<size_t>(packet_len);
        if (!is_initial) {
            offset = next_offset;
            continue;
        }
        if (remaining.size() < hdr_len + 4 + 16) return result;

        std::array<uint8_t, 32> initial_secret{};
        if (!HkdfExtract(spec->salt, dcid, initial_secret)) return result;
        std::array<uint8_t, 32> client_secret{};
        if (!HkdfExpandLabel(initial_secret, "client in", client_secret)) return result;
        std::array<uint8_t, 16> hp_key{};
        std::array<uint8_t, 16> key{};
        std::array<uint8_t, 12> iv{};
        std::string hp_label;
        hp_label.append(spec->label_prefix);
        hp_label.append(" hp");
        std::string key_label;
        key_label.append(spec->label_prefix);
        key_label.append(" key");
        std::string iv_label;
        iv_label.append(spec->label_prefix);
        iv_label.append(" iv");
        if (!HkdfExpandLabel(client_secret, hp_label, hp_key) ||
            !HkdfExpandLabel(client_secret, key_label, key) ||
            !HkdfExpandLabel(client_secret, iv_label, iv)) {
            return result;
        }

        std::array<uint8_t, 16> sample{};
        std::array<uint8_t, 16> mask{};
        std::memcpy(sample.data(), remaining.data() + hdr_len + 4, 16);
        if (!AesEcbEncrypt(hp_key, sample, mask)) return result;
        remaining[0] ^= mask[0] & 0x0f;
        const int pn_len = (remaining[0] & 0x03) + 1;
        for (int i = 0; i < pn_len; ++i) {
            remaining[hdr_len + static_cast<size_t>(i)] ^= mask[static_cast<size_t>(i) + 1];
        }

        std::array<uint8_t, 12> nonce = iv;
        for (int i = 0; i < pn_len; ++i) {
            nonce[12 - pn_len + i] ^= remaining[hdr_len + static_cast<size_t>(i)];
        }
        const size_t ext_hdr_len = hdr_len + static_cast<size_t>(pn_len);
        const auto ciphertext = remaining.subspan(
            ext_hdr_len, static_cast<size_t>(packet_len) - static_cast<size_t>(pn_len));
        const auto aad = remaining.first(ext_hdr_len);
        std::vector<uint8_t> decrypted;
        if (!AesGcmDecrypt(key, nonce, aad, ciphertext, decrypted)) return result;

        size_t frame = 0;
        while (frame < decrypted.size()) {
            uint8_t frame_type = decrypted[frame++];
            while (frame_type == 0x00 && frame < decrypted.size()) {
                frame_type = decrypted[frame++];
            }
            auto payload = std::span<const uint8_t>(decrypted).subspan(frame);
            size_t local = 0;
            auto consume_varint = [&](uint64_t& value) {
                if (!ReadVarint(payload, local, value)) return false;
                return true;
            };
            switch (frame_type) {
                case 0x00:
                    break;
                case 0x01:
                    break;
                case 0x02:
                case 0x03: {
                    uint64_t ignored = 0;
                    uint64_t ack_range_count = 0;
                    if (!consume_varint(ignored) || !consume_varint(ignored) ||
                        !consume_varint(ack_range_count) || !consume_varint(ignored)) {
                        return result;
                    }
                    for (uint64_t i = 0; i < ack_range_count; ++i) {
                        if (!consume_varint(ignored) || !consume_varint(ignored)) {
                            return result;
                        }
                    }
                    if (frame_type == 0x03) {
                        if (!consume_varint(ignored) || !consume_varint(ignored) ||
                            !consume_varint(ignored)) {
                            return result;
                        }
                    }
                    frame += local;
                    break;
                }
                case 0x06: {
                    uint64_t crypto_offset = 0;
                    uint64_t crypto_len = 0;
                    if (!consume_varint(crypto_offset) || !consume_varint(crypto_len)) {
                        return result;
                    }
                    if (local + crypto_len > payload.size()) return result;
                    const auto needed = crypto_offset + crypto_len;
                    if (needed > 32767) return result;
                    if (crypto.size() < needed) crypto.resize(static_cast<size_t>(needed));
                    std::memcpy(crypto.data() + crypto_offset,
                                payload.data() + local,
                                static_cast<size_t>(crypto_len));
                    frame += local + static_cast<size_t>(crypto_len);
                    break;
                }
                case 0x1c: {
                    uint64_t ignored = 0;
                    uint64_t reason_len = 0;
                    if (!consume_varint(ignored) || !consume_varint(ignored) ||
                        !consume_varint(reason_len) ||
                        local + reason_len > payload.size()) {
                        return result;
                    }
                    frame += local + static_cast<size_t>(reason_len);
                    break;
                }
                default:
                    return result;
            }
        }

        TlsSniffer tls;
        if (auto sni = tls.ParseHandshake(crypto); sni) {
            result.success = true;
            result.protocol = constants::protocol::kQuic;
            result.domain.assign(*sni);
            return result;
        }
        offset = next_offset;
    }
    return result;
}

}  // namespace acpp
