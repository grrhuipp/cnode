#include "../vmess_crypto.hpp"
#include "../account.hpp"

#include <openssl/rand.h>
#include <openssl/evp.h>

#include <cstring>
#include <zlib.h>

namespace acpp {
namespace vmess {

void CachedAESKey::InitDecryptKey(const uint8_t* k) {
    std::memcpy(key, k, 16);
}

void CachedAESKey::ECBDecrypt(const uint8_t* ciphertext, uint8_t* plaintext) const {
    AES128ECBDecrypt(key, ciphertext, plaintext);
}

void AES128ECBEncrypt(const uint8_t* key, const uint8_t* plaintext, uint8_t* ciphertext) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return;
    EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, key, nullptr);
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    int out_len = 0;
    EVP_EncryptUpdate(ctx, ciphertext, &out_len, plaintext, 16);
    EVP_CIPHER_CTX_free(ctx);
}

void AES128ECBDecrypt(const uint8_t* key, const uint8_t* ciphertext, uint8_t* plaintext) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return;
    EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, key, nullptr);
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    int out_len = 0;
    EVP_DecryptUpdate(ctx, plaintext, &out_len, ciphertext, 16);
    EVP_CIPHER_CTX_free(ctx);
}

uint32_t CRC32(const uint8_t* data, size_t len) {
    return crc32(0L, data, static_cast<uInt>(len));
}

void RandomBytes(uint8_t* buf, size_t len) {
    RAND_bytes(buf, static_cast<int>(len));
}

void GenerateAuthID(const uint8_t* auth_key, int64_t timestamp, uint8_t* out_auth_id) {
    uint8_t plaintext[16];

    for (int i = 7; i >= 0; i--) {
        plaintext[7 - i] = static_cast<uint8_t>(timestamp >> (i * 8));
    }

    RAND_bytes(plaintext + 8, 4);

    uint32_t crc = CRC32(plaintext, 12);
    plaintext[12] = static_cast<uint8_t>(crc >> 24);
    plaintext[13] = static_cast<uint8_t>(crc >> 16);
    plaintext[14] = static_cast<uint8_t>(crc >> 8);
    plaintext[15] = static_cast<uint8_t>(crc);

    AES128ECBEncrypt(auth_key, plaintext, out_auth_id);
}

}  // namespace vmess
}  // namespace acpp
