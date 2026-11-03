#include "vmess_cipher.hpp"

#include <openssl/evp.h>

#include <cstring>
#include <new>
#include <stdexcept>
#include <utility>

namespace acpp {
namespace vmess {

// ============================================================================
// VMessCipher 实现
// ============================================================================

// OpenSSL 实现（使用 EVP_CIPHER API）
// 优化：预分配 EVP_CIPHER_CTX，避免每次加解密都分配/释放
VMessCipher::VMessCipher(Security security, const uint8_t* key, const uint8_t* iv)
    : security_(security) {
    std::memcpy(iv_.data(), iv, iv_.size());
    const EVP_CIPHER* algorithm = nullptr;
    std::span<const uint8_t> actual_key(key, 16);
    std::array<uint8_t, 32> expanded{};
    if (security == Security::CHACHA20_POLY1305) {
        GenerateChaCha20Key(key, expanded.data());
        actual_key = expanded;
        algorithm = EVP_chacha20_poly1305();
    } else if (security == Security::AES_128_GCM) {
        algorithm = EVP_aes_128_gcm();
    }
    if (algorithm && (!encryptor_.Configure(algorithm, actual_key) ||
                      !decryptor_.Configure(algorithm, actual_key)))
        throw std::runtime_error("VMess AEAD initialization failed");
}

VMessCipher::VMessCipher(Security security, const uint8_t* key, const uint8_t* iv,
                         proxy::AeadDirection direction)
    : security_(security) {
    std::memcpy(iv_.data(), iv, iv_.size());
    const EVP_CIPHER* algorithm = nullptr;
    std::span<const uint8_t> actual_key(key, 16);
    std::array<uint8_t, 32> expanded{};
    if (security == Security::CHACHA20_POLY1305) {
        GenerateChaCha20Key(key, expanded.data());
        actual_key = expanded;
        algorithm = EVP_chacha20_poly1305();
    } else if (security == Security::AES_128_GCM) {
        algorithm = EVP_aes_128_gcm();
    }
    if (algorithm) {
        const bool ok = direction == proxy::AeadDirection::Encrypt
            ? encryptor_.Configure(algorithm, actual_key)
            : decryptor_.Configure(algorithm, actual_key);
        if (!ok) {
            throw std::runtime_error("VMess AEAD initialization failed");
        }
    }
}

ssize_t VMessCipher::Encrypt(const uint8_t* plaintext, size_t len, uint8_t* ciphertext) {
    if (security_ == Security::NONE || security_ == Security::ZERO) {
        if (len > 0 && plaintext) memcpy(ciphertext, plaintext, len);
        return static_cast<ssize_t>(len);
    }

    std::array<uint8_t, 12> nonce{};
    BuildNonce(count_++, nonce.data());
    const auto result = encryptor_.Process(nonce, {plaintext, len}, {},
                                           {ciphertext, len + GCM_TAG_SIZE});
    return result ? static_cast<ssize_t>(*result) : -1;
}

ssize_t VMessCipher::Decrypt(const uint8_t* ciphertext, size_t len, uint8_t* plaintext) {
    if (security_ == Security::NONE || security_ == Security::ZERO) {
        memcpy(plaintext, ciphertext, len);
        return static_cast<ssize_t>(len);
    }

    if (len < GCM_TAG_SIZE) return -1;
    std::array<uint8_t, 12> nonce{};
    BuildNonce(count_++, nonce.data());
    const auto result = decryptor_.Process(nonce, {ciphertext, len}, {},
                                           {plaintext, len - GCM_TAG_SIZE});
    return result ? static_cast<ssize_t>(*result) : -1;
}

size_t VMessCipher::Overhead() const {
    switch (security_) {
        case Security::AES_128_GCM:
        case Security::CHACHA20_POLY1305:
            return GCM_TAG_SIZE;
        default:
            return 0;
    }
}

void VMessCipher::GenerateChaCha20Key(const uint8_t* key16, uint8_t* key32) {
    const std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>
        ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!ctx) throw std::bad_alloc();
    unsigned int md_len = 0;
    if (EVP_DigestInit_ex(ctx.get(), EVP_md5(), nullptr) != 1 ||
        EVP_DigestUpdate(ctx.get(), key16, 16) != 1 ||
        EVP_DigestFinal_ex(ctx.get(), key32, &md_len) != 1 || md_len != 16 ||
        EVP_DigestInit_ex(ctx.get(), EVP_md5(), nullptr) != 1 ||
        EVP_DigestUpdate(ctx.get(), key32, 16) != 1 ||
        EVP_DigestFinal_ex(ctx.get(), key32 + 16, &md_len) != 1 || md_len != 16)
        throw std::runtime_error("VMess key derivation failed");
}

void VMessCipher::BuildNonce(uint16_t count, uint8_t* nonce) {
    nonce[0] = (count >> 8) & 0xFF;
    nonce[1] = count & 0xFF;
    memcpy(nonce + 2, iv_.data() + 2, 10);
}

// ============================================================================
// ShakeMask keeps a small batch of actual SHAKE128 output.
// ============================================================================

ShakeMask::ShakeMask(const uint8_t* nonce) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) throw std::bad_alloc();
    const EVP_MD* md = EVP_shake128();
    if (!md || EVP_DigestInit_ex(ctx, md, nullptr) != 1 ||
        EVP_DigestUpdate(ctx, nonce, 16) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("VMess length-mask initialization failed");
    }
    ctx_ = ctx;
}

ShakeMask::~ShakeMask() {
    if (ctx_) {
        EVP_MD_CTX_free(ctx_);
    }
}

ShakeMask::ShakeMask(ShakeMask&& other) noexcept
    : ctx_(std::exchange(other.ctx_, nullptr))
    , offset_(other.offset_) {
    std::memcpy(buffer_, other.buffer_, kBufferSize);
    other.offset_ = kBufferSize;
}

ShakeMask& ShakeMask::operator=(ShakeMask&& other) noexcept {
    if (this == &other) {
        return *this;
    }
    if (ctx_) {
        EVP_MD_CTX_free(ctx_);
    }
    ctx_ = std::exchange(other.ctx_, nullptr);
    std::memcpy(buffer_, other.buffer_, kBufferSize);
    offset_ = other.offset_;
    other.offset_ = kBufferSize;
    return *this;
}

void ShakeMask::Refill() {
    if (!ctx_ || EVP_DigestSqueeze(ctx_, buffer_, kBufferSize) != 1)
        throw std::runtime_error("VMess length-mask generation failed");
    offset_ = 0;
}

uint16_t ShakeMask::NextMask() {
    if (offset_ + 2 > kBufferSize) {
        Refill();
    }

    uint16_t result = (static_cast<uint16_t>(buffer_[offset_]) << 8) |
                      static_cast<uint16_t>(buffer_[offset_ + 1]);
    offset_ += 2;
    return result;
}

}  // namespace vmess
}  // namespace acpp
