#pragma once

#include "shadowsocks_crypto.hpp"

#include "acppnode/common/buf/multi_buffer.hpp"

#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace acpp::ss::detail {

// One AEAD record may legally carry more than one relay Buffer (16KB for
// classic Shadowsocks and 64KB for SS2022). Keep one EVP context for the whole
// record while emitting plaintext into bounded 8KB Buffer blocks.
class StreamAeadDecryptor {
public:
    explicit StreamAeadDecryptor(const SsAeadCipher& cipher)
        : type_(cipher.Type())
        , key_size_(cipher.Key().size()) {
        if (key_size_ == 0 || key_size_ > key_.size()) {
            return;
        }
        std::memcpy(key_.data(), cipher.Key().data(), key_size_);
        ctx_ = EVP_CIPHER_CTX_new();
    }

    ~StreamAeadDecryptor() {
        if (ctx_) {
            EVP_CIPHER_CTX_free(ctx_);
        }
    }

    StreamAeadDecryptor(const StreamAeadDecryptor&) = delete;
    StreamAeadDecryptor& operator=(const StreamAeadDecryptor&) = delete;

    [[nodiscard]] bool Init(const uint8_t* nonce) noexcept {
        if (!ctx_ || !nonce) {
            return false;
        }

        const EVP_CIPHER* cipher = GetCipher(type_);
        return cipher &&
            EVP_CIPHER_CTX_reset(ctx_) == 1 &&
            EVP_DecryptInit_ex(ctx_, cipher, nullptr, nullptr, nullptr) == 1 &&
            EVP_CIPHER_CTX_ctrl(ctx_, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr) == 1 &&
            EVP_DecryptInit_ex(ctx_, nullptr, nullptr, key_.data(), nonce) == 1;
    }

    [[nodiscard]] bool Update(const uint8_t* ciphertext,
                              size_t ciphertext_len,
                              uint8_t* output,
                              int* out_len) noexcept {
        if (!ctx_ || !ciphertext || !output || !out_len ||
            ciphertext_len > static_cast<size_t>(INT_MAX)) {
            return false;
        }
        return EVP_DecryptUpdate(
            ctx_, output, out_len, ciphertext,
            static_cast<int>(ciphertext_len)) == 1;
    }

    [[nodiscard]] bool Final(const uint8_t* tag) noexcept {
        if (!ctx_ || !tag ||
            EVP_CIPHER_CTX_ctrl(
                ctx_, EVP_CTRL_AEAD_SET_TAG,
                static_cast<int>(SsAeadCipher::kTagSize),
                const_cast<uint8_t*>(tag)) != 1) {
            return false;
        }

        int final_len = 0;
        uint8_t dummy[1]{};
        return EVP_DecryptFinal_ex(ctx_, dummy, &final_len) == 1 &&
            final_len == 0;
    }

private:
    [[nodiscard]] static const EVP_CIPHER* GetCipher(
        SsCipherType type) noexcept {
        switch (BaseCipherType(type)) {
            case SsCipherType::AES_128_GCM:
                return EVP_aes_128_gcm();
            case SsCipherType::AES_256_GCM:
                return EVP_aes_256_gcm();
            case SsCipherType::CHACHA20_POLY1305:
                return EVP_chacha20_poly1305();
            default:
                return nullptr;
        }
    }

    SsCipherType type_;
    std::array<uint8_t, 32> key_{};
    size_t key_size_ = 0;
    EVP_CIPHER_CTX* ctx_ = nullptr;
};

[[nodiscard]] inline bool DecryptStreamPayload(
    StreamAeadDecryptor& decryptor,
    const uint8_t* ciphertext,
    size_t payload_len,
    const uint8_t* tag,
    buf::MultiBuffer& output) {
    if ((payload_len > 0 && !ciphertext) || !tag) {
        return false;
    }

    buf::MultiBuffer decoded;
    decoded.reserve(
        (payload_len + buf::Buffer::kSize - 1) / buf::Buffer::kSize);

    size_t offset = 0;
    while (offset < payload_len) {
        buf::BufferGuard plain{buf::Buffer::New()};
        if (!plain) {
            return false;
        }

        const size_t chunk = std::min(
            payload_len - offset,
            static_cast<size_t>(plain->Available()));
        int produced = 0;
        if (!decryptor.Update(
                ciphertext + offset,
                chunk,
                plain->Tail().data(),
                &produced) ||
            produced < 0 ||
            static_cast<size_t>(produced) != chunk) {
            return false;
        }

        plain->Produce(static_cast<uint32_t>(produced));
        decoded.push_back(plain.release());
        offset += chunk;
    }

    if (!decryptor.Final(tag)) {
        return false;
    }

    decoded.MoveTo(output);
    return true;
}

}  // namespace acpp::ss::detail
