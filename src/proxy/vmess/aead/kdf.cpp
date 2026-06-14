#include "../vmess_crypto.hpp"
#include "acppnode/common/unsafe.hpp"

#include <openssl/hmac.h>

#include <cstring>

namespace acpp {
namespace vmess {

// HMAC-SHA256
static void HMAC_SHA256_Impl(const void* key, int key_len,
                              const uint8_t* data, size_t data_len,
                              uint8_t* out) {
    unsigned int out_len = 32;
    HMAC(EVP_sha256(), key, key_len, data, data_len, out, &out_len);
}

// VMess KDF 递归实现 (嵌套 HMAC-SHA256)
static void vmess_kdf_recursive(
    const uint8_t* data, size_t data_len,
    std::span<const std::string_view> path,
    size_t depth,
    uint8_t* out) {

    static const char* kKdfSalt = "VMess AEAD KDF";

    if (depth == 0) {
        HMAC_SHA256_Impl(kKdfSalt, static_cast<int>(strlen(kKdfSalt)), data, data_len, out);
        return;
    }

    const std::string_view key = path[depth - 1];

    alignas(16) uint8_t k_padded[64] = {0};

    if (key.size() <= 64) {
        memcpy(k_padded, key.data(), key.size());
    } else {
        vmess_kdf_recursive(unsafe::ptr_cast<const uint8_t>(key.data()),
                            key.size(), path, depth - 1, k_padded);
    }

    alignas(16) uint8_t ipad[64], opad[64];
    for (int i = 0; i < 64; i++) {
        ipad[i] = k_padded[i] ^ 0x36;
        opad[i] = k_padded[i] ^ 0x5c;
    }

    alignas(16) uint8_t inner_input[512];
    if (64 + data_len > sizeof(inner_input)) {
        memory::ByteVector inner_vec(64 + data_len);
        memcpy(inner_vec.data(), ipad, 64);
        memcpy(inner_vec.data() + 64, data, data_len);

        uint8_t inner_hash[32];
        vmess_kdf_recursive(inner_vec.data(), 64 + data_len, path, depth - 1, inner_hash);

        alignas(16) uint8_t outer_input[96];
        memcpy(outer_input, opad, 64);
        memcpy(outer_input + 64, inner_hash, 32);
        vmess_kdf_recursive(outer_input, 96, path, depth - 1, out);
        return;
    }

    memcpy(inner_input, ipad, 64);
    memcpy(inner_input + 64, data, data_len);

    uint8_t inner_hash[32];
    vmess_kdf_recursive(inner_input, 64 + data_len, path, depth - 1, inner_hash);

    alignas(16) uint8_t outer_input[96];
    memcpy(outer_input, opad, 64);
    memcpy(outer_input + 64, inner_hash, 32);
    vmess_kdf_recursive(outer_input, 96, path, depth - 1, out);
}

void KDF(const uint8_t* key, size_t key_len,
         std::span<const std::string_view> path,
         uint8_t* out, size_t out_len) {
    uint8_t result[32];
    vmess_kdf_recursive(key, key_len, path, path.size(), result);
    memcpy(out, result, std::min(out_len, size_t(32)));
}

std::array<uint8_t, 16> KDF16(const uint8_t* key, size_t key_len,
                               std::span<const std::string_view> path) {
    std::array<uint8_t, 16> result;
    KDF(key, key_len, path, result.data(), 16);
    return result;
}

}  // namespace vmess
}  // namespace acpp
