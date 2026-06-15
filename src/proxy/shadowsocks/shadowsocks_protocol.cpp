#include "shadowsocks_crypto.hpp"

#include "acppnode/core/constants.hpp"

#include <blake3.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/sha.h>

#include <algorithm>
#include <cctype>
#include <cstring>
#include <limits>
#include <utility>
#include <vector>

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
    if (lower == std::string(constants::protocol::kSs2022Blake3Aes128Gcm)) {
        return SsCipherInfo{SsCipherType::AES_128_GCM_2022, 16, 16};
    }
    if (lower == std::string(constants::protocol::kSs2022Blake3Aes256Gcm)) {
        return SsCipherInfo{SsCipherType::AES_256_GCM_2022, 32, 32};
    }
    if (lower == std::string(constants::protocol::kSs2022Blake3Chacha20Poly1305)) {
        return SsCipherInfo{SsCipherType::CHACHA20_POLY1305_2022, 32, 32};
    }
    return std::nullopt;
}

bool Is2022Cipher(SsCipherType type) noexcept {
    switch (type) {
        case SsCipherType::AES_128_GCM_2022:
        case SsCipherType::AES_256_GCM_2022:
        case SsCipherType::CHACHA20_POLY1305_2022:
            return true;
        default:
            return false;
    }
}

bool Is2022Cipher(const SsCipherInfo& info) noexcept {
    return Is2022Cipher(info.type);
}

bool Is2022AesCipher(SsCipherType type) noexcept {
    return type == SsCipherType::AES_128_GCM_2022 ||
           type == SsCipherType::AES_256_GCM_2022;
}

SsCipherType BaseCipherType(SsCipherType type) noexcept {
    switch (type) {
        case SsCipherType::AES_128_GCM_2022:
            return SsCipherType::AES_128_GCM;
        case SsCipherType::AES_256_GCM_2022:
            return SsCipherType::AES_256_GCM;
        case SsCipherType::CHACHA20_POLY1305_2022:
            return SsCipherType::CHACHA20_POLY1305;
        default:
            return type;
    }
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

KeyBytes Decode2022Psk(std::string_view password, size_t key_size) {
    KeyBytes key;
    if (key_size == 0 || key_size > KeyBytes::kMaxSize) {
        return key;
    }

    std::string encoded;
    encoded.reserve(password.size() + 3);
    for (const char ch : password) {
        if (ch == '\r' || ch == '\n' || ch == '\t' || ch == ' ') {
            continue;
        }
        if (ch == '-') {
            encoded.push_back('+');
        } else if (ch == '_') {
            encoded.push_back('/');
        } else {
            encoded.push_back(ch);
        }
    }
    if (encoded.empty() || encoded.size() % 4 == 1) {
        return key;
    }
    while (encoded.size() % 4 != 0) {
        encoded.push_back('=');
    }

    std::vector<uint8_t> decoded((encoded.size() / 4) * 3);
    const int decoded_len = EVP_DecodeBlock(
        decoded.data(),
        reinterpret_cast<const uint8_t*>(encoded.data()),
        static_cast<int>(encoded.size()));
    if (decoded_len < 0) {
        return key;
    }
    size_t plain_len = static_cast<size_t>(decoded_len);
    while (!encoded.empty() && encoded.back() == '=') {
        --plain_len;
        encoded.pop_back();
    }
    if (plain_len < key_size) {
        return key;
    }

    if (plain_len == key_size) {
        key.assign(std::span<const uint8_t>(decoded.data(), plain_len));
        return key;
    }

    std::array<uint8_t, SHA256_DIGEST_LENGTH> digest{};
    SHA256(decoded.data(), plain_len, digest.data());
    key.assign(std::span<const uint8_t>(digest.data(), key_size));
    return key;
}

KeyBytes BuildMasterKey(std::string_view password, const SsCipherInfo& info) {
    if (Is2022Cipher(info)) {
        return Decode2022Psk(password, info.key_size);
    }
    return DeriveKey(std::string(password), info.key_size);
}

bool Derive2022Subkey(const uint8_t* key, size_t key_size,
                      const uint8_t* salt, size_t salt_size,
                      uint8_t* out_subkey) {
    if (!key || !salt || !out_subkey ||
        key_size == 0 || key_size > KeyBytes::kMaxSize ||
        salt_size == 0 || salt_size > KeyBytes::kMaxSize) {
        return false;
    }
    blake3_hasher hasher;
    blake3_hasher_init_derive_key(&hasher, "shadowsocks 2022 session subkey");
    blake3_hasher_update(&hasher, key, key_size);
    blake3_hasher_update(&hasher, salt, salt_size);
    blake3_hasher_finalize(&hasher, out_subkey, key_size);
    return true;
}

bool Derive2022IdentitySubkey(const uint8_t* key, size_t key_size,
                              const uint8_t* salt, size_t salt_size,
                              uint8_t* out_key) {
    if (!key || !salt || !out_key ||
        key_size == 0 || key_size > KeyBytes::kMaxSize ||
        salt_size == 0 || salt_size > KeyBytes::kMaxSize) {
        return false;
    }
    blake3_hasher hasher;
    blake3_hasher_init_derive_key(&hasher, "shadowsocks 2022 identity subkey");
    blake3_hasher_update(&hasher, key, key_size);
    blake3_hasher_update(&hasher, salt, salt_size);
    blake3_hasher_finalize(&hasher, out_key, key_size);
    return true;
}

bool Hash2022Psk(std::span<const uint8_t> key, std::span<uint8_t, 16> out_hash) {
    if (key.empty()) {
        return false;
    }
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, key.data(), key.size());
    blake3_hasher_finalize(&hasher, out_hash.data(), out_hash.size());
    return true;
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
    switch (BaseCipherType(type)) {
        case SsCipherType::AES_128_GCM:       return EVP_aes_128_gcm();
        case SsCipherType::AES_256_GCM:       return EVP_aes_256_gcm();
        case SsCipherType::CHACHA20_POLY1305:  return EVP_chacha20_poly1305();
        default:                              return nullptr;
    }
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
