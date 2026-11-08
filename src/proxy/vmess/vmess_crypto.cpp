#include "vmess_crypto.hpp"

#include <openssl/sha.h>
#include <openssl/evp.h>

#include <memory>
#include <new>
#include <stdexcept>

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

uint32_t FNV1a32(const uint8_t* data, size_t len) {
    uint32_t hash = 0x811c9dc5;
    for (size_t i = 0; i < len; i++) {
        hash ^= data[i];
        hash *= 0x01000193;
    }
    return hash;
}
}  // namespace vmess
