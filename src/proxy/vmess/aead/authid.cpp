#include "../vmess_crypto.hpp"

#include <openssl/rand.h>

#include <zlib.h>

#include <stdexcept>

namespace vmess {

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

}  // namespace vmess
