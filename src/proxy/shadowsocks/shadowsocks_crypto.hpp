#pragma once

#include "acppnode/proxy/shadowsocks/shadowsocks_protocol.hpp"

#include <openssl/evp.h>

#include <array>
#include <chrono>
#include <cstdint>
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

// ============================================================================
// SS2022 (AEAD-2022) 共享原语
//
// 大端整数读写、Unix 时间戳、AES-ECB 单块（identity header）等握手辅助逻辑，
// 客户端（client.cpp）与服务端（server.cpp）完全一致，集中在协议私有头里避免
// 两份逐字复制。仅服务握手语义，不对外暴露为请求链路对象。
// ============================================================================
static constexpr size_t kSs2022MaxChunkPayload = 0xFFFF;
static constexpr size_t kSs2022RequestFixedHeaderSize = 1 + 8 + 2;

inline void PutU16BE(uint8_t* out, uint16_t value) noexcept {
    out[0] = static_cast<uint8_t>(value >> 8);
    out[1] = static_cast<uint8_t>(value & 0xFF);
}

inline uint16_t GetU16BE(const uint8_t* data) noexcept {
    return static_cast<uint16_t>((data[0] << 8) | data[1]);
}

inline void PutU64BE(uint8_t* out, uint64_t value) noexcept {
    for (int i = 7; i >= 0; --i) {
        out[static_cast<size_t>(7 - i)] = static_cast<uint8_t>(value >> (8 * i));
    }
}

inline uint64_t GetU64BE(const uint8_t* data) noexcept {
    uint64_t value = 0;
    for (size_t i = 0; i < 8; ++i) {
        value = (value << 8) | data[i];
    }
    return value;
}

inline uint64_t UnixSecondsNow() noexcept {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
}

inline bool TimestampFresh(uint64_t remote, uint64_t now) noexcept {
    constexpr uint64_t kMaxSkew = 30;
    return remote <= now + kMaxSkew && remote + kMaxSkew >= now;
}

inline bool AesBlockCrypt(std::span<const uint8_t> key,
                          std::span<const uint8_t, 16> input,
                          std::span<uint8_t, 16> output,
                          bool encrypt) {
    const EVP_CIPHER* cipher = nullptr;
    if (key.size() == 16) {
        cipher = EVP_aes_128_ecb();
    } else if (key.size() == 32) {
        cipher = EVP_aes_256_ecb();
    } else {
        return false;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return false;
    }

    int out_len = 0;
    int final_len = 0;
    const bool ok =
        (encrypt
            ? EVP_EncryptInit_ex(ctx, cipher, nullptr, key.data(), nullptr) == 1
            : EVP_DecryptInit_ex(ctx, cipher, nullptr, key.data(), nullptr) == 1) &&
        EVP_CIPHER_CTX_set_padding(ctx, 0) == 1 &&
        (encrypt
            ? EVP_EncryptUpdate(ctx, output.data(), &out_len, input.data(), 16) == 1
            : EVP_DecryptUpdate(ctx, output.data(), &out_len, input.data(), 16) == 1) &&
        out_len == 16 &&
        (encrypt
            ? EVP_EncryptFinal_ex(ctx, output.data() + out_len, &final_len) == 1
            : EVP_DecryptFinal_ex(ctx, output.data() + out_len, &final_len) == 1) &&
        final_len == 0;

    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

}  // namespace acpp::ss
