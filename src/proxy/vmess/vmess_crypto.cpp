#include "vmess_crypto.hpp"

#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

#include <algorithm>
#include <cstring>

namespace acpp {
namespace vmess {

std::optional<std::array<uint8_t, 16>> ParseUUID(const std::string& uuid_str) {
    std::array<uint8_t, 16> result;

    std::string clean;
    clean.reserve(32);
    for (char c : uuid_str) {
        if (c != '-') {
            clean += c;
        }
    }

    if (clean.size() != 32) {
        return std::nullopt;
    }

    for (size_t i = 0; i < 16; ++i) {
        char buf[3] = {clean[i * 2], clean[i * 2 + 1], '\0'};
        char* end;
        long val = strtol(buf, &end, 16);
        if (*end != '\0') {
            return std::nullopt;
        }
        result[i] = static_cast<uint8_t>(val);
    }

    return result;
}

std::array<uint8_t, 16> MD5Hash(const uint8_t* data, size_t len) {
    std::array<uint8_t, 16> result;
    unsigned int md_len = 16;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_md5(), nullptr);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, result.data(), &md_len);
    EVP_MD_CTX_free(ctx);
    return result;
}

std::array<uint8_t, 32> SHA256Hash(const uint8_t* data, size_t len) {
    std::array<uint8_t, 32> result;
    SHA256(data, len, result.data());
    return result;
}

std::array<uint8_t, 16> HMAC_MD5(const uint8_t* key, size_t key_len,
                                  const uint8_t* data, size_t data_len) {
    std::array<uint8_t, 16> result;
    unsigned int out_len = 16;
    HMAC(EVP_md5(), key, static_cast<int>(key_len), data, data_len, result.data(), &out_len);
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

void SHAKE128(const uint8_t* input, size_t input_len,
              uint8_t* output, size_t output_len) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return;

    const EVP_MD* md = EVP_shake128();
    if (!md) {
        EVP_MD_CTX_free(ctx);
        return;
    }

    if (EVP_DigestInit_ex(ctx, md, nullptr) == 1 &&
        EVP_DigestUpdate(ctx, input, input_len) == 1) {
        EVP_DigestFinalXOF(ctx, output, output_len);
    }

    EVP_MD_CTX_free(ctx);
}

}  // namespace vmess
}  // namespace acpp
