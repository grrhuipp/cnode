#include "../vmess_crypto.hpp"
#include "../vmess_request.hpp"

#include <openssl/evp.h>
#include <openssl/err.h>

#include <algorithm>
#include <cstring>

namespace acpp {
namespace vmess {

namespace {
class SslErrorGuard {
public:
    SslErrorGuard() : success_(false) {}
    ~SslErrorGuard() {
        if (!success_) {
            ERR_clear_error();
        }
    }
    void MarkSuccess() { success_ = true; }
private:
    bool success_;
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

    SslErrorGuard ssl_guard;

    const size_t data_len = len - GCM_TAG_SIZE;
    if (data_len > plaintext_capacity) return false;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    int out_len = 0, final_len = 0;
    bool ok = false;

    do {
        if (EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr) != 1) break;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, static_cast<int>(nonce_len), nullptr) != 1) break;
        if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, nonce) != 1) break;

        if (aad && aad_len > 0) {
            if (EVP_DecryptUpdate(ctx, nullptr, &out_len, aad, static_cast<int>(aad_len)) != 1) break;
        }

        if (EVP_DecryptUpdate(ctx, plaintext, &out_len, ciphertext, static_cast<int>(data_len)) != 1) break;

        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, GCM_TAG_SIZE,
                               const_cast<uint8_t*>(ciphertext + data_len)) != 1) break;

        if (EVP_DecryptFinal_ex(ctx, plaintext + out_len, &final_len) != 1) break;

        ok = true;
    } while (0);

    EVP_CIPHER_CTX_free(ctx);

    if (!ok) return false;

    ssl_guard.MarkSuccess();
    plaintext_len = static_cast<size_t>(out_len + final_len);
    return true;
}

bool AES128GCMEncrypt(
    const uint8_t* key, const uint8_t* nonce,
    const uint8_t* aad, size_t aad_len,
    const uint8_t* plaintext, size_t len,
    uint8_t* ciphertext, uint8_t* tag) {

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    int out_len = 0, final_len = 0;
    bool ok = false;

    do {
        if (EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr) != 1) break;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr) != 1) break;
        if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, nonce) != 1) break;

        if (aad && aad_len > 0) {
            if (EVP_EncryptUpdate(ctx, nullptr, &out_len, aad, static_cast<int>(aad_len)) != 1) break;
        }

        if (EVP_EncryptUpdate(ctx, ciphertext, &out_len, plaintext, static_cast<int>(len)) != 1) break;
        if (EVP_EncryptFinal_ex(ctx, ciphertext + out_len, &final_len) != 1) break;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, GCM_TAG_SIZE, tag) != 1) break;

        ok = true;
    } while (0);

    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

}  // namespace vmess
}  // namespace acpp
