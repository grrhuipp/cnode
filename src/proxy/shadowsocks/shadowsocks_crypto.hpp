#pragma once

#include "shadowsocks_protocol.hpp"
#include "common/byte_reader.hpp"
#include "../aead.hpp"

#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/crypto.h>

#include <array>
#include <chrono>
#include <cstdint>
#include <span>
#include <variant>

namespace ss {

// 从主密钥 + 随机 salt 派生子密钥（HKDF-SHA1，ss-subkey）
[[nodiscard]] bool DeriveSubkey(const uint8_t* key, size_t key_size,
                                const uint8_t* salt, size_t salt_size,
                                uint8_t* out_subkey);

// 每次 Encrypt/Decrypt 后由调用方自增 nonce 计数器。
class SsAeadCipher {
public:
    // Authentication trials bind the first candidate key through ResetKey.
    SsAeadCipher(SsCipherType type, proxy::AeadDirection direction);
    SsAeadCipher(SsCipherType type, const uint8_t* key, size_t key_size,
                 proxy::AeadDirection direction);
    ~SsAeadCipher() = default;

    SsAeadCipher(const SsAeadCipher&) = delete;
    SsAeadCipher& operator=(const SsAeadCipher&) = delete;
    SsAeadCipher(SsAeadCipher&& other) noexcept = default;
    SsAeadCipher& operator=(SsAeadCipher&& other) noexcept = default;

    [[nodiscard]] bool Encrypt(const uint8_t* nonce,
                               const uint8_t* plaintext,
                               size_t plaintext_len,
                               uint8_t* output) noexcept;

    [[nodiscard]] bool Decrypt(const uint8_t* nonce,
                               const uint8_t* ciphertext,
                               size_t ciphertext_len,
                               uint8_t* output) noexcept;

    [[nodiscard]] bool ResetKey(const uint8_t* key, size_t key_size);

    static constexpr size_t kTagSize = 16;

private:
    SsCipherType type_;
    std::variant<proxy::AeadEncryptor, proxy::AeadDecryptor> context_;
};

static constexpr size_t kMaxChunkPayload = 0x3FFF;

// ============================================================================
// SS2022 (AEAD-2022) 共享原语
//
// Unix 时间戳、AES-ECB 单块（identity header）等握手辅助逻辑，
// 客户端（client.cpp）与服务端（server.cpp）完全一致，集中在协议私有头里避免
// 两份逐字复制。仅服务握手语义，不对外暴露为请求链路对象。
// ============================================================================
static constexpr size_t kSs2022MaxChunkPayload = 0xFFFF;
static constexpr size_t kSs2022RequestFixedHeaderSize = 1 + 8 + 2;

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
    if (key.size() != 16 && key.size() != 32) return false;

    // A single SS2022 header block needs no EVP session or heap allocation.
    // BoringSSL's public AES APIs retain hardware/software dispatch. The schedule
    // belongs only to this synchronous operation, never to an idle connection.
    AES_KEY schedule;
    const auto bits = static_cast<unsigned>(key.size() * 8);
    const int status = encrypt
        ? AES_set_encrypt_key(key.data(), bits, &schedule)
        : AES_set_decrypt_key(key.data(), bits, &schedule);
    if (status == 0) {
        if (encrypt) AES_encrypt(input.data(), output.data(), &schedule);
        else AES_decrypt(input.data(), output.data(), &schedule);
    }
    OPENSSL_cleanse(&schedule, sizeof(schedule));
    return status == 0;
}

}  // namespace ss
