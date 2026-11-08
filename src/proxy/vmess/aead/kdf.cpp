#include "../vmess_crypto.hpp"
#include "../vmess_request.hpp"
#include "common/unsafe.hpp"

#include <openssl/hmac.h>
#include <openssl/mem.h>

#include <algorithm>
#include <cstring>
#include <stdexcept>

namespace vmess {

namespace {

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
            memcpy(k_padded, key.data(), key.size());
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
    memcpy(inner_input, ipad, 64);
    if (data_len > 0) {
        memcpy(inner_input + 64, data, data_len);
    }

    uint8_t inner_hash[32];
    VmessKdfRecursive(inner_input, 64 + data_len, path, depth - 1, inner_hash);

    alignas(16) uint8_t outer_input[96];
    memcpy(outer_input, opad, 64);
    memcpy(outer_input + 64, inner_hash, 32);
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
        memcpy(out, result, std::min(out_len, size_t(32)));
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

}  // namespace vmess
