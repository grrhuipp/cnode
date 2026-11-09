#include "../../aead.hpp"
#include "../vmess_crypto.hpp"
#include "../vmess_request.hpp"

#include <openssl/aead.h>
#include <openssl/err.h>

namespace vmess {
bool AES128GCMDecryptTo(
    const uint8_t* key, const uint8_t* nonce, size_t nonce_len,
    const uint8_t* ciphertext, size_t len,
    const uint8_t* aad, size_t aad_len,
    uint8_t* plaintext, size_t plaintext_capacity,
    size_t& plaintext_len) {
    if (!proxy::OpenOneShotAead(
            EVP_aead_aes_128_gcm(),
            {key, 16},
            {nonce, nonce_len},
            {ciphertext, len},
            {aad, aad_len},
            {plaintext, plaintext_capacity},
            plaintext_len,
            GCM_TAG_SIZE)) {
        ERR_clear_error();
        return false;
    }
    return true;
}

bool AES128GCMEncrypt(
    const uint8_t* key, const uint8_t* nonce,
    const uint8_t* aad, size_t aad_len,
    const uint8_t* plaintext, size_t len,
    uint8_t* ciphertext, uint8_t* tag) {
    if (!proxy::SealScatterOneShotAead(
            EVP_aead_aes_128_gcm(),
            {key, 16},
            {nonce, 12},
            {plaintext, len},
            {aad, aad_len},
            ciphertext,
            {tag, GCM_TAG_SIZE})) {
        ERR_clear_error();
        return false;
    }
    return true;
}
}  // namespace vmess
