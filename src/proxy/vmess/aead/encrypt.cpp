#include "../vmess_crypto.hpp"
#include "../vmess_request.hpp"

#include <openssl/aead.h>
#include <openssl/err.h>
#include <openssl/mem.h>

#include <algorithm>
#include <cstring>

namespace vmess {

namespace {
struct ScopedAeadCtx {
    EVP_AEAD_CTX ctx;
    ScopedAeadCtx() noexcept { EVP_AEAD_CTX_zero(&ctx); }
    ~ScopedAeadCtx() noexcept {
        EVP_AEAD_CTX_cleanup(&ctx);
        OPENSSL_cleanse(&ctx, sizeof(ctx));
    }
};
}  // namespace

bool AES128GCMDecryptTo(
    const uint8_t* key, const uint8_t* nonce, size_t nonce_len,
    const uint8_t* ciphertext, size_t len,
    const uint8_t* aad, size_t aad_len,
    uint8_t* plaintext, size_t plaintext_capacity,
    size_t& plaintext_len) {
    plaintext_len = 0;
    if (len < GCM_TAG_SIZE) return false;
    const size_t data_len = len - GCM_TAG_SIZE;
    if (data_len > plaintext_capacity) return false;

    ScopedAeadCtx aead;
    if (EVP_AEAD_CTX_init(&aead.ctx, EVP_aead_aes_128_gcm(),
                          key, 16, GCM_TAG_SIZE, nullptr) != 1) {
        ERR_clear_error();
        return false;
    }
    size_t out_len = 0;
    if (EVP_AEAD_CTX_open(&aead.ctx, plaintext, &out_len, plaintext_capacity,
                          nonce, nonce_len,
                          ciphertext, len,
                          aad, aad_len) != 1) {
        ERR_clear_error();
        return false;
    }
    plaintext_len = out_len;
    return true;
}

bool AES128GCMEncrypt(
    const uint8_t* key, const uint8_t* nonce,
    const uint8_t* aad, size_t aad_len,
    const uint8_t* plaintext, size_t len,
    uint8_t* ciphertext, uint8_t* tag) {
    ScopedAeadCtx aead;
    if (EVP_AEAD_CTX_init(&aead.ctx, EVP_aead_aes_128_gcm(),
                          key, 16, GCM_TAG_SIZE, nullptr) != 1) {
        ERR_clear_error();
        return false;
    }
    size_t tag_len = 0;
    if (EVP_AEAD_CTX_seal_scatter(&aead.ctx, ciphertext,
                                  tag, &tag_len, GCM_TAG_SIZE,
                                  nonce, 12,
                                  plaintext, len,
                                  nullptr, 0,
                                  aad, aad_len) != 1 ||
        tag_len != GCM_TAG_SIZE) {
        ERR_clear_error();
        return false;
    }
    return true;
}
}  // namespace vmess
