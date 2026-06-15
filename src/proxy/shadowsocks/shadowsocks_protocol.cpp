#include "shadowsocks_crypto.hpp"

#include "acppnode/core/constants.hpp"

#include <openssl/evp.h>
#include <openssl/kdf.h>

#include <algorithm>
#include <cctype>
#include <cstring>
#include <limits>
#include <utility>

namespace acpp::ss {

// ============================================================================
// ParseCipherMethod
// ============================================================================
std::optional<SsCipherInfo> ParseCipherMethod(std::string_view method) {
    // 转小写比较
    std::string lower(method);
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    if (lower == std::string(constants::protocol::kAes128Gcm)) {
        return SsCipherInfo{SsCipherType::AES_128_GCM, 16, 16};
    }
    if (lower == std::string(constants::protocol::kAes256Gcm)) {
        return SsCipherInfo{SsCipherType::AES_256_GCM, 32, 32};
    }
    if (lower == std::string(constants::protocol::kChacha20IetfPoly1305) ||
        lower == "chacha20-poly1305") {
        return SsCipherInfo{SsCipherType::CHACHA20_POLY1305, 32, 32};
    }
    return std::nullopt;
}

// ============================================================================
// DeriveKey — EVP_BytesToKey + MD5
// ============================================================================
KeyBytes DeriveKey(const std::string& password, size_t key_size) {
    KeyBytes key;
    if (key_size > KeyBytes::kMaxSize) {
        return key;
    }

    uint8_t prev[16];
    size_t prev_len = 0;
    size_t written = 0;
    const auto* pw = reinterpret_cast<const uint8_t*>(password.data());
    const size_t pw_len = password.size();

    // 复用 EVP_MD_CTX，避免循环内反复 new/free
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();

    while (written < key_size) {
        // D_i = MD5(D_{i-1} || password)
        EVP_DigestInit_ex(ctx, EVP_md5(), nullptr);
        if (prev_len > 0) {
            EVP_DigestUpdate(ctx, prev, prev_len);
        }
        EVP_DigestUpdate(ctx, pw, pw_len);

        unsigned int len = 16;
        EVP_DigestFinal_ex(ctx, prev, &len);
        prev_len = 16;

        const size_t chunk = std::min<size_t>(16, key_size - written);
        std::memcpy(key.bytes.data() + written, prev, chunk);
        written += chunk;
    }

    EVP_MD_CTX_free(ctx);

    key.size = key_size;
    return key;
}

// ============================================================================
// DeriveSubkey — HKDF-SHA1("ss-subkey")
// ============================================================================
bool DeriveSubkey(const uint8_t* key, size_t key_size,
                  const uint8_t* salt, size_t salt_size,
                  uint8_t* out_subkey) {
    const char* info = "ss-subkey";
    const size_t info_size = std::strlen(info);
    constexpr size_t kMaxOpenSslParamSize = static_cast<size_t>(std::numeric_limits<int>::max());
    if (!key || !salt || !out_subkey ||
        key_size > kMaxOpenSslParamSize ||
        salt_size > kMaxOpenSslParamSize ||
        info_size > kMaxOpenSslParamSize) {
        return false;
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (!ctx) {
        return false;
    }

    size_t out_len = key_size;
    const bool ok =
        EVP_PKEY_derive_init(ctx) == 1 &&
        EVP_PKEY_CTX_hkdf_mode(ctx, EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND) == 1 &&
        EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha1()) == 1 &&
        EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt, salt_size) == 1 &&
        EVP_PKEY_CTX_set1_hkdf_key(ctx, key, key_size) == 1 &&
        EVP_PKEY_CTX_add1_hkdf_info(
            ctx,
            reinterpret_cast<const uint8_t*>(info),
            info_size) == 1 &&
        EVP_PKEY_derive(ctx, out_subkey, &out_len) == 1 &&
        out_len == key_size;

    EVP_PKEY_CTX_free(ctx);
    return ok;
}

// ============================================================================
// SsAeadCipher
// ============================================================================
SsAeadCipher::SsAeadCipher(SsCipherType type, const uint8_t* key, size_t key_size)
    : type_(type)
    , key_size_(key_size <= key_.size() ? key_size : 0) {
    if (key_size_ == 0 || !key) {
        return;
    }
    std::memcpy(key_.data(), key, key_size_);
    ctx_ = EVP_CIPHER_CTX_new();
}

SsAeadCipher::~SsAeadCipher() {
    if (ctx_) {
        EVP_CIPHER_CTX_free(ctx_);
        ctx_ = nullptr;
    }
}

SsAeadCipher::SsAeadCipher(SsAeadCipher&& other) noexcept
    : type_(other.type_)
    , key_(other.key_)
    , key_size_(other.key_size_)
    , ctx_(std::exchange(other.ctx_, nullptr)) {
    other.key_size_ = 0;
}

SsAeadCipher& SsAeadCipher::operator=(SsAeadCipher&& other) noexcept {
    if (this == &other) {
        return *this;
    }
    if (ctx_) {
        EVP_CIPHER_CTX_free(ctx_);
    }
    type_ = other.type_;
    key_ = other.key_;
    key_size_ = other.key_size_;
    ctx_ = std::exchange(other.ctx_, nullptr);
    other.key_size_ = 0;
    return *this;
}

static const EVP_CIPHER* GetCipher(SsCipherType type) noexcept {
    switch (type) {
        case SsCipherType::AES_128_GCM:       return EVP_aes_128_gcm();
        case SsCipherType::AES_256_GCM:       return EVP_aes_256_gcm();
        case SsCipherType::CHACHA20_POLY1305:  return EVP_chacha20_poly1305();
    }
    return nullptr;
}

bool SsAeadCipher::Encrypt(const uint8_t* nonce,
                            const uint8_t* plaintext, size_t plaintext_len,
                            uint8_t* output) noexcept {
    if (!ctx_) return false;

    const EVP_CIPHER* cipher = GetCipher(type_);
    if (!cipher) return false;

    EVP_CIPHER_CTX_reset(ctx_);

    int out_len = 0;

    if (EVP_EncryptInit_ex(ctx_, cipher, nullptr, nullptr, nullptr) != 1) return false;
    if (EVP_CIPHER_CTX_ctrl(ctx_, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr) != 1) return false;
    if (EVP_EncryptInit_ex(ctx_, nullptr, nullptr, key_.data(), nonce) != 1) return false;

    if (EVP_EncryptUpdate(ctx_, output, &out_len,
                          plaintext, static_cast<int>(plaintext_len)) != 1) return false;

    int final_len = 0;
    if (EVP_EncryptFinal_ex(ctx_, output + out_len, &final_len) != 1) return false;

    // 写入 GCM/Poly1305 tag
    if (EVP_CIPHER_CTX_ctrl(ctx_, EVP_CTRL_AEAD_GET_TAG, 16,
                             output + plaintext_len) != 1) return false;

    return true;
}

bool SsAeadCipher::Decrypt(const uint8_t* nonce,
                            const uint8_t* ciphertext, size_t ciphertext_len,
                            uint8_t* output) noexcept {
    if (!ctx_ || ciphertext_len < 16) return false;

    const EVP_CIPHER* cipher = GetCipher(type_);
    if (!cipher) return false;

    EVP_CIPHER_CTX_reset(ctx_);

    const size_t data_len = ciphertext_len - 16;
    const uint8_t* tag_ptr = ciphertext + data_len;

    int out_len = 0;

    if (EVP_DecryptInit_ex(ctx_, cipher, nullptr, nullptr, nullptr) != 1) return false;
    if (EVP_CIPHER_CTX_ctrl(ctx_, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr) != 1) return false;
    if (EVP_DecryptInit_ex(ctx_, nullptr, nullptr, key_.data(), nonce) != 1) return false;

    if (EVP_DecryptUpdate(ctx_, output, &out_len,
                          ciphertext, static_cast<int>(data_len)) != 1) return false;

    // 设置 tag
    if (EVP_CIPHER_CTX_ctrl(ctx_, EVP_CTRL_AEAD_SET_TAG, 16,
                             const_cast<uint8_t*>(tag_ptr)) != 1) return false;

    int final_len = 0;
    if (EVP_DecryptFinal_ex(ctx_, output + out_len, &final_len) != 1) return false;

    return true;
}

}  // namespace acpp::ss
