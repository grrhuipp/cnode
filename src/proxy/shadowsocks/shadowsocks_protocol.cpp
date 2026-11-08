#include "shadowsocks_crypto.hpp"

#include "core/constants.hpp"
#include "core/naming.hpp"

#include <blake3.h>
#include <openssl/base64.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hkdf.h>

#include <algorithm>
#include <array>
#include <climits>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <utility>

namespace ss {

// ============================================================================
// ParseCipherMethod
// ============================================================================
std::optional<SsCipherInfo> ParseCipherMethod(std::string_view method) {
    const std::string lower = naming::LowerAscii(std::string(method));

    if (lower == constants::protocol::kAes128Gcm) {
        return SsCipherInfo{SsCipherType::AES_128_GCM, 16, 16};
    }
    if (lower == constants::protocol::kAes256Gcm) {
        return SsCipherInfo{SsCipherType::AES_256_GCM, 32, 32};
    }
    if (lower == constants::protocol::kChacha20IetfPoly1305 ||
        lower == "chacha20-poly1305") {
        return SsCipherInfo{SsCipherType::CHACHA20_POLY1305, 32, 32};
    }
    if (lower == constants::protocol::kSs2022Blake3Aes128Gcm) {
        return SsCipherInfo{SsCipherType::AES_128_GCM_2022, 16, 16};
    }
    if (lower == constants::protocol::kSs2022Blake3Aes256Gcm) {
        return SsCipherInfo{SsCipherType::AES_256_GCM_2022, 32, 32};
    }
    if (lower == constants::protocol::kSs2022Blake3Chacha20Poly1305) {
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
KeyBytes DeriveKey(std::string_view password, size_t key_size) {
    KeyBytes key;
    if (key_size > KeyBytes::kMaxSize) {
        return key;
    }

    uint8_t prev[16]{};
    struct CleansePrev {
        uint8_t (&buf)[16];
        ~CleansePrev() noexcept { OPENSSL_cleanse(buf, sizeof(buf)); }
    } cleanse_prev{prev};
    size_t prev_len = 0;
    size_t written = 0;
    const auto* pw = reinterpret_cast<const uint8_t*>(password.data());
    const size_t pw_len = password.size();

    // 复用 EVP_MD_CTX，避免循环内反复 new/free
    const std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>
        ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!ctx) throw std::bad_alloc();

    while (written < key_size) {
        // D_i = MD5(D_{i-1} || password)
        unsigned int len = 0;
        if (EVP_DigestInit_ex(ctx.get(), EVP_md5(), nullptr) != 1 ||
            (prev_len && EVP_DigestUpdate(ctx.get(), prev, prev_len) != 1) ||
            EVP_DigestUpdate(ctx.get(), pw, pw_len) != 1 ||
            EVP_DigestFinal_ex(ctx.get(), prev, &len) != 1 || len != 16)
            throw std::runtime_error("Shadowsocks key derivation failed");
        prev_len = 16;

        const size_t chunk = std::min<size_t>(16, key_size - written);
        std::memcpy(key.bytes.data() + written, prev, chunk);
        written += chunk;
    }

    key.size = key_size;
    return key;
}

KeyBytes Decode2022Psk(std::string_view password, size_t key_size) {
    KeyBytes key;
    if (key_size == 0 || key_size > KeyBytes::kMaxSize) {
        return key;
    }

    std::string encoded;
    struct CleanseEncoded {
        std::string& buf;
        ~CleanseEncoded() noexcept {
            if (!buf.empty()) OPENSSL_cleanse(buf.data(), buf.size());
        }
    } cleanse_encoded{encoded};
    encoded.reserve(44);
    for (const char ch : password) {
        if (ch == '\r' || ch == '\n' || ch == '\t' || ch == ' ') {
            continue;
        }
        if (encoded.size() >= 44) {
            return key;
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
        if (encoded.size() >= 44) {
            return key;
        }
        encoded.push_back('=');
    }

    size_t pad_count = 0;
    const size_t first_pad = encoded.find('=');
    if (first_pad != std::string::npos) {
        pad_count = encoded.size() - first_pad;
        if (pad_count > 2) {
            return key;
        }
        for (size_t i = first_pad; i < encoded.size(); ++i) {
            if (encoded[i] != '=') {
                return key;
            }
        }
    }

    auto sextet_value = [](char c) noexcept -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '+') return 62;
        if (c == '/') return 63;
        return -1;
    };
    if (pad_count == 1) {
        const int last_sextet = sextet_value(encoded[encoded.size() - 2]);
        if (last_sextet < 0 || (last_sextet & 0x03) != 0) {
            return key;
        }
    } else if (pad_count == 2) {
        const int last_sextet = sextet_value(encoded[encoded.size() - 3]);
        if (last_sextet < 0 || (last_sextet & 0x0F) != 0) {
            return key;
        }
    }

    std::array<uint8_t, 36> decoded{};
    struct CleanseDecoded {
        std::array<uint8_t, 36>& buf;
        ~CleanseDecoded() noexcept { OPENSSL_cleanse(buf.data(), buf.size()); }
    } cleanse_decoded{decoded};
    const int decoded_len = EVP_DecodeBlock(
        decoded.data(),
        reinterpret_cast<const uint8_t*>(encoded.data()),
        static_cast<int>(encoded.size()));
    if (decoded_len < 0 || static_cast<size_t>(decoded_len) < pad_count) {
        return key;
    }
    const size_t plain_len = static_cast<size_t>(decoded_len) - pad_count;
    if (plain_len != key_size) {
        return key;
    }
    key.assign(std::span<const uint8_t>(decoded.data(), plain_len));
    return key;
}

KeyBytes Build2022UserKeyFromUuid(
    std::string_view uuid,
    const SsCipherInfo& info) {
    KeyBytes key;
    if (!Is2022Cipher(info.type) ||
        info.key_size == 0 ||
        info.key_size > KeyBytes::kMaxSize ||
        uuid.size() < info.key_size) {
        return key;
    }

    // V2Board publishes the raw UUID to node backends, while subscriptions use
    // base64(substr(uuid, 0, key_size)). The decoded SS2022 PSK is therefore
    // exactly the first key_size UUID bytes; build it here in the protocol-owned
    // credential cold path instead of leaking SS key construction into panel code.
    key.assign(std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(uuid.data()),
        info.key_size));
    return key;
}

KeyBytes BuildMasterKey(std::string_view password, const SsCipherInfo& info) {
    if (Is2022Cipher(info.type)) {
        return Decode2022Psk(password, info.key_size);
    }
    return DeriveKey(password, info.key_size);
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
    OPENSSL_cleanse(&hasher, sizeof(hasher));
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
    OPENSSL_cleanse(&hasher, sizeof(hasher));
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
    OPENSSL_cleanse(&hasher, sizeof(hasher));
    return true;
}

// ============================================================================
// DeriveSubkey — HKDF-SHA1("ss-subkey")
// ============================================================================
bool DeriveSubkey(const uint8_t* key, size_t key_size,
                  const uint8_t* salt, size_t salt_size,
                  uint8_t* out_subkey) {
    static constexpr uint8_t info[] = "ss-subkey";
    constexpr size_t kMaxOpenSslParamSize = static_cast<size_t>(std::numeric_limits<int>::max());
    if (!key || !salt || !out_subkey ||
        key_size > kMaxOpenSslParamSize ||
        salt_size > kMaxOpenSslParamSize) {
        return false;
    }

    // The one-shot API owns operation-local state and cleanses its PRK.
    // Avoid allocating a generic PKEY context and copies of key/salt/info for
    // every authentication attempt in a native UDP packet's user search.
    return HKDF(out_subkey, key_size, EVP_sha1(), key, key_size,
                salt, salt_size, info, sizeof(info) - 1) == 1;
}

// ============================================================================
// SsAeadCipher
// ============================================================================
namespace {
const EVP_AEAD* GetCipher(SsCipherType type) noexcept {
    switch (BaseCipherType(type)) {
        case SsCipherType::AES_128_GCM: return EVP_aead_aes_128_gcm();
        case SsCipherType::AES_256_GCM: return EVP_aead_aes_256_gcm();
        case SsCipherType::CHACHA20_POLY1305: return EVP_aead_chacha20_poly1305();
        default: return nullptr;
    }
}
}

SsAeadCipher::SsAeadCipher(SsCipherType type, proxy::AeadDirection direction)
    : type_(type) {
    if (direction == proxy::AeadDirection::Decrypt)
        context_.emplace<proxy::AeadDecryptor>();
}

SsAeadCipher::SsAeadCipher(SsCipherType type, const uint8_t* key, size_t key_size,
                         proxy::AeadDirection direction)
    : SsAeadCipher(type, direction) {
    if (!ResetKey(key, key_size))
        throw std::runtime_error("Shadowsocks AEAD initialization failed");
}

bool SsAeadCipher::ResetKey(const uint8_t* key, size_t key_size) {
    const auto configure = [&](auto& context) {
        return context.Configure(GetCipher(type_),
                                  key ? std::span<const uint8_t>(key, key_size) : std::span<const uint8_t>{});
    };
    return std::visit(configure, context_);
}

bool SsAeadCipher::Encrypt(const uint8_t* nonce, const uint8_t* plaintext,
                          size_t plaintext_len, uint8_t* output) noexcept {
    auto* context = std::get_if<proxy::AeadEncryptor>(&context_);
    return context && nonce && output && (plaintext || plaintext_len == 0) &&
        plaintext_len <= static_cast<size_t>(INT_MAX) &&
        context->Process(std::span<const uint8_t, 12>(nonce, 12),
                         {plaintext, plaintext_len}, {},
                         {output, plaintext_len + kTagSize}).has_value();
}

bool SsAeadCipher::Decrypt(const uint8_t* nonce, const uint8_t* ciphertext,
                          size_t ciphertext_len, uint8_t* output) noexcept {
    auto* context = std::get_if<proxy::AeadDecryptor>(&context_);
    return context && nonce && ciphertext && ciphertext_len >= kTagSize &&
        (output || ciphertext_len == kTagSize) &&
        context->Process(std::span<const uint8_t, 12>(nonce, 12),
                         {ciphertext, ciphertext_len}, {},
                         {output, ciphertext_len - kTagSize}).has_value();
}

}  // namespace ss
