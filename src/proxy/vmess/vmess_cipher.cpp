#include "vmess_cipher.hpp"

#include <openssl/evp.h>

#include <cstring>
#include <utility>

namespace acpp {
namespace vmess {

// ============================================================================
// VMessCipher 实现
// ============================================================================

// OpenSSL 实现（使用 EVP_CIPHER API）
// 优化：预分配 EVP_CIPHER_CTX，避免每次加解密都分配/释放
VMessCipher::VMessCipher(Security security, const uint8_t* key, const uint8_t* iv)
    : security_(security), count_(0), enc_ctx_(nullptr), dec_ctx_(nullptr), ctx_initialized_(false) {
    std::memcpy(key_.data(), key, 16);
    std::memcpy(iv_.data(), iv, 16);

    if (security_ == Security::AES_128_GCM || security_ == Security::CHACHA20_POLY1305) {
        if (security_ == Security::CHACHA20_POLY1305) {
            GenerateChaCha20Key(key_.data(), key32_.data());
        }

        // 预分配加密和解密上下文（直接成员指针，无额外堆分配）
        enc_ctx_ = EVP_CIPHER_CTX_new();
        dec_ctx_ = EVP_CIPHER_CTX_new();

        ctx_initialized_ = (enc_ctx_ != nullptr && dec_ctx_ != nullptr);
    }
}

VMessCipher::~VMessCipher() {
    if (enc_ctx_) EVP_CIPHER_CTX_free(static_cast<EVP_CIPHER_CTX*>(enc_ctx_));
    if (dec_ctx_) EVP_CIPHER_CTX_free(static_cast<EVP_CIPHER_CTX*>(dec_ctx_));
}

VMessCipher::VMessCipher(VMessCipher&& other) noexcept
    : security_(other.security_)
    , key_(other.key_)
    , key32_(other.key32_)
    , iv_(other.iv_)
    , count_(other.count_)
    , enc_ctx_(std::exchange(other.enc_ctx_, nullptr))
    , dec_ctx_(std::exchange(other.dec_ctx_, nullptr))
    , ctx_initialized_(std::exchange(other.ctx_initialized_, false)) {}

VMessCipher& VMessCipher::operator=(VMessCipher&& other) noexcept {
    if (this == &other) {
        return *this;
    }
    if (enc_ctx_) EVP_CIPHER_CTX_free(static_cast<EVP_CIPHER_CTX*>(enc_ctx_));
    if (dec_ctx_) EVP_CIPHER_CTX_free(static_cast<EVP_CIPHER_CTX*>(dec_ctx_));
    security_ = other.security_;
    key_ = other.key_;
    key32_ = other.key32_;
    iv_ = other.iv_;
    count_ = other.count_;
    enc_ctx_ = std::exchange(other.enc_ctx_, nullptr);
    dec_ctx_ = std::exchange(other.dec_ctx_, nullptr);
    ctx_initialized_ = std::exchange(other.ctx_initialized_, false);
    return *this;
}

ssize_t VMessCipher::Encrypt(const uint8_t* plaintext, size_t len, uint8_t* ciphertext) {
    if (security_ == Security::NONE || security_ == Security::ZERO) {
        if (len > 0 && plaintext) memcpy(ciphertext, plaintext, len);
        return static_cast<ssize_t>(len);
    }

    if (!ctx_initialized_) return -1;

    uint8_t nonce[12];
    BuildNonce(count_++, nonce);

    EVP_CIPHER_CTX* ctx = static_cast<EVP_CIPHER_CTX*>(enc_ctx_);

    // 重置上下文以便复用
    EVP_CIPHER_CTX_reset(ctx);

    const EVP_CIPHER* cipher;
    const uint8_t* actual_key;

    if (security_ == Security::CHACHA20_POLY1305) {
        cipher = EVP_chacha20_poly1305();
        actual_key = key32_.data();
    } else {
        cipher = EVP_aes_128_gcm();
        actual_key = key_.data();
    }

    int out_len = 0;
    int final_len = 0;

    if (EVP_EncryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr) != 1) {
        return -1;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr) != 1) {
        return -1;
    }

    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, actual_key, nonce) != 1) {
        return -1;
    }

    if (EVP_EncryptUpdate(ctx, ciphertext, &out_len, plaintext, static_cast<int>(len)) != 1) {
        return -1;
    }

    if (EVP_EncryptFinal_ex(ctx, ciphertext + out_len, &final_len) != 1) {
        return -1;
    }

    out_len += final_len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, GCM_TAG_SIZE, ciphertext + out_len) != 1) {
        return -1;
    }

    return static_cast<ssize_t>(out_len + GCM_TAG_SIZE);
}

ssize_t VMessCipher::Decrypt(const uint8_t* ciphertext, size_t len, uint8_t* plaintext) {
    if (security_ == Security::NONE || security_ == Security::ZERO) {
        memcpy(plaintext, ciphertext, len);
        return static_cast<ssize_t>(len);
    }

    if (len < GCM_TAG_SIZE) return -1;
    if (!ctx_initialized_) return -1;

    uint8_t nonce[12];
    BuildNonce(count_++, nonce);

    EVP_CIPHER_CTX* ctx = static_cast<EVP_CIPHER_CTX*>(dec_ctx_);

    // 重置上下文以便复用
    EVP_CIPHER_CTX_reset(ctx);

    const EVP_CIPHER* cipher;
    const uint8_t* actual_key;

    if (security_ == Security::CHACHA20_POLY1305) {
        cipher = EVP_chacha20_poly1305();
        actual_key = key32_.data();
    } else {
        cipher = EVP_aes_128_gcm();
        actual_key = key_.data();
    }

    size_t ciphertext_len = len - GCM_TAG_SIZE;
    int out_len = 0;
    int final_len = 0;

    if (EVP_DecryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr) != 1) {
        return -1;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr) != 1) {
        return -1;
    }

    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, actual_key, nonce) != 1) {
        return -1;
    }

    if (EVP_DecryptUpdate(ctx, plaintext, &out_len, ciphertext, static_cast<int>(ciphertext_len)) != 1) {
        return -1;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, GCM_TAG_SIZE,
                           const_cast<uint8_t*>(ciphertext + ciphertext_len)) != 1) {
        return -1;
    }

    if (EVP_DecryptFinal_ex(ctx, plaintext + out_len, &final_len) != 1) {
        return -1;
    }

    return static_cast<ssize_t>(out_len + final_len);
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
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    unsigned int md_len = 16;

    EVP_DigestInit_ex(md_ctx, EVP_md5(), nullptr);
    EVP_DigestUpdate(md_ctx, key16, 16);
    EVP_DigestFinal_ex(md_ctx, key32, &md_len);

    EVP_DigestInit_ex(md_ctx, EVP_md5(), nullptr);
    EVP_DigestUpdate(md_ctx, key32, 16);
    EVP_DigestFinal_ex(md_ctx, key32 + 16, &md_len);

    EVP_MD_CTX_free(md_ctx);
}

void VMessCipher::BuildNonce(uint16_t count, uint8_t* nonce) {
    nonce[0] = (count >> 8) & 0xFF;
    nonce[1] = count & 0xFF;
    memcpy(nonce + 2, iv_.data() + 2, 10);
}

// ============================================================================
// ShakeMask 实现 - 优化版：固定 4KB 数组
// ============================================================================

ShakeMask::ShakeMask(const uint8_t* nonce) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (ctx) {
        const EVP_MD* md = EVP_shake128();
        if (md && EVP_DigestInit_ex(ctx, md, nullptr) == 1 &&
            EVP_DigestUpdate(ctx, nonce, 16) == 1) {
            ctx_ = ctx;
        } else {
            EVP_MD_CTX_free(ctx);
        }
    }
}

ShakeMask::~ShakeMask() {
    if (ctx_) {
        EVP_MD_CTX_free(static_cast<EVP_MD_CTX*>(ctx_));
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
        EVP_MD_CTX_free(static_cast<EVP_MD_CTX*>(ctx_));
    }
    ctx_ = std::exchange(other.ctx_, nullptr);
    std::memcpy(buffer_, other.buffer_, kBufferSize);
    offset_ = other.offset_;
    other.offset_ = kBufferSize;
    return *this;
}

void ShakeMask::Refill() {
    if (ctx_) {
        EVP_DigestSqueeze(static_cast<EVP_MD_CTX*>(ctx_), buffer_, kBufferSize);
    } else {
        memset(buffer_, 0, kBufferSize);
    }
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
