#pragma once

#include "acppnode/proxy/shadowsocks/shadowsocks_protocol.hpp"

#include <openssl/evp.h>

#include <array>
#include <span>

namespace acpp::ss {

// 从主密钥 + 随机 salt 派生子密钥（HKDF-SHA1，ss-subkey）
[[nodiscard]] bool DeriveSubkey(const uint8_t* key, size_t key_size,
                                const uint8_t* salt, size_t salt_size,
                                uint8_t* out_subkey);

// 每次 Encrypt/Decrypt 后由调用方自增 nonce 计数器。
class SsAeadCipher {
public:
    SsAeadCipher(SsCipherType type, const uint8_t* key, size_t key_size);
    ~SsAeadCipher();

    SsAeadCipher(const SsAeadCipher&) = delete;
    SsAeadCipher& operator=(const SsAeadCipher&) = delete;
    SsAeadCipher(SsAeadCipher&& other) noexcept;
    SsAeadCipher& operator=(SsAeadCipher&& other) noexcept;

    [[nodiscard]] bool Encrypt(const uint8_t* nonce,
                               const uint8_t* plaintext,
                               size_t plaintext_len,
                               uint8_t* output) noexcept;

    [[nodiscard]] bool Decrypt(const uint8_t* nonce,
                               const uint8_t* ciphertext,
                               size_t ciphertext_len,
                               uint8_t* output) noexcept;

    [[nodiscard]] SsCipherType Type() const noexcept { return type_; }
    [[nodiscard]] std::span<const uint8_t> Key() const noexcept {
        return {key_.data(), key_size_};
    }

    static constexpr size_t kTagSize = 16;

private:
    SsCipherType type_;
    std::array<uint8_t, 32> key_{};
    size_t key_size_ = 0;
    EVP_CIPHER_CTX* ctx_ = nullptr;
};

static constexpr size_t kMaxChunkPayload = 0x3FFF;

}  // namespace acpp::ss
