#include "proxy/vmess/vmess_crypto.hpp"
#include "common/byte_reader.hpp"
#include "proxy/aead.hpp"
#include "common/binary_text_codec.hpp"
#include "common/unsafe.hpp"

#include <openssl/aead.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/mem.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <zlib.h>

#include <algorithm>
#include <cstring>
#include <memory>
#include <new>
#include <stdexcept>
#include <string_view>
#include <utility>
namespace vmess {

std::array<uint8_t, 16> MD5Hash(const uint8_t* data, size_t len) {
    const std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>
        ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!ctx) throw std::bad_alloc();
    std::array<uint8_t, 16> result{};
    unsigned int md_len = 0;
    if (EVP_DigestInit_ex(ctx.get(), EVP_md5(), nullptr) != 1 ||
        EVP_DigestUpdate(ctx.get(), data, len) != 1 ||
        EVP_DigestFinal_ex(ctx.get(), result.data(), &md_len) != 1 ||
        md_len != result.size()) {
        throw std::runtime_error("VMess MD5 digest failed");
    }
    return result;
}

std::array<uint8_t, 32> SHA256Hash(const uint8_t* data, size_t len) {
    std::array<uint8_t, 32> result{};
    SHA256(data, len, result.data());
    return result;
}

uint32_t CRC32(const uint8_t* data, size_t len) {
    return crc32(0L, data, static_cast<uInt>(len));
}

AES_KEY ExpandAuthIDEncryptKey(const std::array<uint8_t, 16>& auth_key) {
    AES_KEY schedule;
    // A rejected 128-bit key is a library fault, never a configuration error.
    if (AES_set_encrypt_key(auth_key.data(), 128, &schedule) != 0) {
        throw std::logic_error("VMess AuthID key schedule rejected a 128-bit key");
    }
    return schedule;
}

void GenerateAuthID(const AES_KEY& auth_id_key, int64_t timestamp, uint8_t* out_auth_id) {
    uint8_t plaintext[16];

    for (int i = 7; i >= 0; i--) {
        plaintext[7 - i] = static_cast<uint8_t>(timestamp >> (i * 8));
    }

    if (RAND_bytes(plaintext + 8, 4) != 1) {
        throw std::runtime_error("VMess AuthID random generation failed");
    }

    uint32_t crc = CRC32(plaintext, 12);
    plaintext[12] = static_cast<uint8_t>(crc >> 24);
    plaintext[13] = static_cast<uint8_t>(crc >> 16);
    plaintext[14] = static_cast<uint8_t>(crc >> 8);
    plaintext[15] = static_cast<uint8_t>(crc);

    AES_encrypt(plaintext, out_auth_id, &auth_id_key);
}

namespace {

constexpr std::string_view kVmessMagic = "c48619fe-8f02-49e0-b9e9-edf763e17e21";

void HmacSha256(const void* key, int key_len,
                const uint8_t* data, size_t data_len,
                uint8_t* out) {
    unsigned int out_len = 0;
    if (!HMAC(EVP_sha256(), key, key_len, data, data_len, out, &out_len) ||
        out_len != 32) {
        throw std::runtime_error("VMess KDF HMAC failed");
    }
}

// VMess KDF：path 的每一层把下一层当作 HMAC 的哈希函数（嵌套 HMAC-SHA256）
void VmessKdfRecursive(
    const uint8_t* data, size_t data_len,
    std::span<const std::string_view> path,
    size_t depth,
    uint8_t* out) {
    if (depth == 0) {
        const std::string_view salt = KDFSalt::VMESS_AEAD_KDF;
        HmacSha256(salt.data(), static_cast<int>(salt.size()), data, data_len, out);
        return;
    }

    const std::string_view key = path[depth - 1];

    alignas(16) uint8_t k_padded[64] = {0};

    if (key.size() <= 64) {
        if (!key.empty()) {
            std::memcpy(k_padded, key.data(), key.size());
        }
    } else {
        VmessKdfRecursive(unsafe::ptr_cast<const uint8_t>(key.data()),
                          key.size(), path, depth - 1, k_padded);
    }

    alignas(16) uint8_t ipad[64], opad[64];
    for (int i = 0; i < 64; i++) {
        ipad[i] = k_padded[i] ^ 0x36;
        opad[i] = k_padded[i] ^ 0x5c;
    }

    alignas(16) uint8_t inner_stack[512];
    memory::ByteVector inner_heap;
    uint8_t* inner_input = inner_stack;
    if (64 + data_len > sizeof(inner_stack)) {
        inner_heap.resize(64 + data_len);
        inner_input = inner_heap.data();
    }
    std::memcpy(inner_input, ipad, 64);
    if (data_len > 0) {
        std::memcpy(inner_input + 64, data, data_len);
    }

    uint8_t inner_hash[32];
    VmessKdfRecursive(inner_input, 64 + data_len, path, depth - 1, inner_hash);

    alignas(16) uint8_t outer_input[96];
    std::memcpy(outer_input, opad, 64);
    std::memcpy(outer_input + 64, inner_hash, 32);
    VmessKdfRecursive(outer_input, 96, path, depth - 1, out);

    OPENSSL_cleanse(k_padded, sizeof(k_padded));
    OPENSSL_cleanse(ipad, sizeof(ipad));
    OPENSSL_cleanse(opad, sizeof(opad));
    OPENSSL_cleanse(inner_input, 64 + data_len);
    OPENSSL_cleanse(inner_hash, sizeof(inner_hash));
    OPENSSL_cleanse(outer_input, sizeof(outer_input));
}

std::string_view AsText(std::span<const uint8_t> bytes) noexcept {
    return {unsafe::ptr_cast<const char>(bytes.data()), bytes.size()};
}

HeaderAeadKey DeriveHeaderKey(std::span<const uint8_t> key_material,
                              std::span<const std::string_view> key_path,
                              std::span<const std::string_view> nonce_path) {
    HeaderAeadKey derived;
    KDF(key_material.data(), key_material.size(), key_path,
        derived.key.data(), derived.key.size());
    KDF(key_material.data(), key_material.size(), nonce_path,
        derived.nonce.data(), derived.nonce.size());
    return derived;
}

}  // namespace

void KDF(const uint8_t* key, size_t key_len,
         std::span<const std::string_view> path,
         uint8_t* out, size_t out_len) {
    uint8_t result[32];
    VmessKdfRecursive(key, key_len, path, path.size(), result);
    if (out_len > 0) {
        std::memcpy(out, result, std::min(out_len, size_t(32)));
    }
    OPENSSL_cleanse(result, sizeof(result));
}

std::array<uint8_t, 16> KDF16(const uint8_t* key, size_t key_len,
                               std::span<const std::string_view> path) {
    std::array<uint8_t, 16> result;
    KDF(key, key_len, path, result.data(), 16);
    return result;
}

HeaderAeadKey RequestHeaderLengthKey(std::span<const uint8_t, 16> cmd_key,
                                     std::span<const uint8_t, 16> auth_id,
                                     std::span<const uint8_t, 8> connection_nonce) {
    const std::array<std::string_view, 3> key_path{
        KDFSalt::VMESS_HEADER_PAYLOAD_LENGTH_AEAD_KEY, AsText(auth_id), AsText(connection_nonce)};
    const std::array<std::string_view, 3> nonce_path{
        KDFSalt::VMESS_HEADER_PAYLOAD_LENGTH_AEAD_IV, AsText(auth_id), AsText(connection_nonce)};
    return DeriveHeaderKey(cmd_key, key_path, nonce_path);
}

HeaderAeadKey RequestHeaderPayloadKey(std::span<const uint8_t, 16> cmd_key,
                                      std::span<const uint8_t, 16> auth_id,
                                      std::span<const uint8_t, 8> connection_nonce) {
    const std::array<std::string_view, 3> key_path{
        KDFSalt::VMESS_HEADER_PAYLOAD_AEAD_KEY, AsText(auth_id), AsText(connection_nonce)};
    const std::array<std::string_view, 3> nonce_path{
        KDFSalt::VMESS_HEADER_PAYLOAD_AEAD_IV, AsText(auth_id), AsText(connection_nonce)};
    return DeriveHeaderKey(cmd_key, key_path, nonce_path);
}

HeaderAeadKey ResponseHeaderLengthKey(std::span<const uint8_t, 16> response_key,
                                      std::span<const uint8_t, 16> response_iv) {
    const std::array<std::string_view, 1> key_path{KDFSalt::AEAD_RESP_HEADER_LEN_KEY};
    const std::array<std::string_view, 1> nonce_path{KDFSalt::AEAD_RESP_HEADER_LEN_IV};
    HeaderAeadKey derived;
    KDF(response_key.data(), response_key.size(), key_path,
        derived.key.data(), derived.key.size());
    KDF(response_iv.data(), response_iv.size(), nonce_path,
        derived.nonce.data(), derived.nonce.size());
    return derived;
}

HeaderAeadKey ResponseHeaderPayloadKey(std::span<const uint8_t, 16> response_key,
                                       std::span<const uint8_t, 16> response_iv) {
    const std::array<std::string_view, 1> key_path{KDFSalt::AEAD_RESP_HEADER_PAYLOAD_KEY};
    const std::array<std::string_view, 1> nonce_path{KDFSalt::AEAD_RESP_HEADER_PAYLOAD_IV};
    HeaderAeadKey derived;
    KDF(response_key.data(), response_key.size(), key_path,
        derived.key.data(), derived.key.size());
    KDF(response_iv.data(), response_iv.size(), nonce_path,
        derived.nonce.data(), derived.nonce.size());
    return derived;
}

std::optional<MemoryAccount> MemoryAccount::FromUUID(std::string_view uuid_str) {
    auto uuid_bytes = ::ParseUuid(uuid_str);
    if (!uuid_bytes) {
        return std::nullopt;
    }
    return FromUuidBytes(*uuid_bytes);
}

MemoryAccount MemoryAccount::FromUuidBytes(const std::array<uint8_t, 16>& uuid) {
    MemoryAccount account;
    account.uuid_bytes = uuid;

    std::array<uint8_t, 16 + kVmessMagic.size()> key_material{};
    std::memcpy(key_material.data(), account.uuid_bytes.data(), account.uuid_bytes.size());
    std::memcpy(key_material.data() + account.uuid_bytes.size(),
                kVmessMagic.data(), kVmessMagic.size());
    account.cmd_key = MD5Hash(key_material.data(), key_material.size());
    OPENSSL_cleanse(key_material.data(), key_material.size());
    const std::array<std::string_view, 1> auth_key_path{
        KDFSalt::AUTH_ID_ENCRYPTION_KEY
    };
    account.auth_key = KDF16(account.cmd_key.data(), 16, auth_key_path);

    return account;
}

// ============================================================================
// VMessCipher 实现
// ============================================================================

VMessCipher::VMessCipher(Security security, const uint8_t* key, const uint8_t* iv)
    : security_(security) {
    std::memcpy(iv_.data(), iv, iv_.size());
    if (security == Security::NONE || security == Security::ZERO) {
        return;
    }
    if (security != Security::AES_128_GCM && security != Security::CHACHA20_POLY1305) {
        throw std::invalid_argument("unsupported VMess body security");
    }
    // ChaCha20-Poly1305 needs 32 bytes: MD5(key16) || MD5(MD5(key16)).
    std::array<uint8_t, 32> expanded{};
    std::span<const uint8_t> actual_key(key, 16);
    const EVP_AEAD* algorithm = EVP_aead_aes_128_gcm();
    if (security == Security::CHACHA20_POLY1305) {
        auto first = MD5Hash(key, 16);
        auto second = MD5Hash(first.data(), first.size());
        std::memcpy(expanded.data(), first.data(), first.size());
        std::memcpy(expanded.data() + first.size(), second.data(), second.size());
        OPENSSL_cleanse(first.data(), first.size());
        OPENSSL_cleanse(second.data(), second.size());
        actual_key = expanded;
        algorithm = EVP_aead_chacha20_poly1305();
    }
    const bool ok = aead_.Configure(algorithm, actual_key);
    OPENSSL_cleanse(expanded.data(), expanded.size());
    if (!ok) {
        throw std::runtime_error("VMess AEAD initialization failed");
    }
}

ssize_t VMessCipher::Encrypt(const uint8_t* plaintext, size_t len, uint8_t* ciphertext) {
    if (security_ == Security::NONE || security_ == Security::ZERO) {
        if (len > 0 && plaintext != ciphertext) std::memcpy(ciphertext, plaintext, len);
        return static_cast<ssize_t>(len);
    }

    std::array<uint8_t, 12> nonce{};
    BuildNonce(count_++, nonce.data());
    const auto result = aead_.Seal(nonce, {plaintext, len}, {}, {ciphertext, len + GCM_TAG_SIZE});
    return result ? static_cast<ssize_t>(*result) : -1;
}

ssize_t VMessCipher::Decrypt(const uint8_t* ciphertext, size_t len, uint8_t* plaintext) {
    if (security_ == Security::NONE || security_ == Security::ZERO) {
        if (len > 0 && plaintext != ciphertext) std::memcpy(plaintext, ciphertext, len);
        return static_cast<ssize_t>(len);
    }

    if (len < GCM_TAG_SIZE) return -1;
    std::array<uint8_t, 12> nonce{};
    BuildNonce(count_++, nonce.data());
    const auto result = aead_.Open(nonce, {ciphertext, len}, {}, {plaintext, len - GCM_TAG_SIZE});
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

    uint16_t result = LoadU16BE(&buffer_[offset_]);
    offset_ += 2;
    return result;
}
}  // namespace vmess
