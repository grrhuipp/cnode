#pragma once

// ============================================================================
// vmess_crypto.hpp — VMess 密码学原语
//
// 职责：底层加密函数、密钥派生（KDF）、哈希、随机数生成。
// 不包含任何协议结构体或用户管理逻辑。
// 底层 OpenSSL 失败属于系统故障，统一以异常上报，不返回未初始化输出。
// ============================================================================

#include "common.hpp"
#include "common/allocator.hpp"
#include <openssl/aes.h>
#include "common/unsafe.hpp"
#include <array>
#include <span>
#include <string_view>
#include <cstdint>

namespace vmess {

// ============================================================================
// 哈希函数
// ============================================================================

std::array<uint8_t, 16> MD5Hash(const uint8_t* data, size_t len);
std::array<uint8_t, 32> SHA256Hash(const uint8_t* data, size_t len);

// ============================================================================
// VMess AEAD KDF（嵌套 HMAC-SHA256）
// ============================================================================

void KDF(const uint8_t* key, size_t key_len,
         std::span<const std::string_view> path,
         uint8_t* out, size_t out_len);

// KDF16 — 返回 16 字节派生密钥
std::array<uint8_t, 16> KDF16(const uint8_t* key, size_t key_len,
                               std::span<const std::string_view> path);

// AES-128-GCM 头部密钥与 nonce
struct HeaderAeadKey {
    std::array<uint8_t, 16> key{};
    std::array<uint8_t, 12> nonce{};
    ~HeaderAeadKey() noexcept {
        ::SecureZeroMemory(key.data(), key.size());
        ::SecureZeroMemory(nonce.data(), nonce.size());
    }
};

// 请求头：由 cmd_key、AuthID 与 8 字节连接 nonce 派生
HeaderAeadKey RequestHeaderLengthKey(std::span<const uint8_t, 16> cmd_key,
                                     std::span<const uint8_t, 16> auth_id,
                                     std::span<const uint8_t, 8> connection_nonce);
HeaderAeadKey RequestHeaderPayloadKey(std::span<const uint8_t, 16> cmd_key,
                                      std::span<const uint8_t, 16> auth_id,
                                      std::span<const uint8_t, 8> connection_nonce);

// 响应头：由响应 body key/IV 派生
HeaderAeadKey ResponseHeaderLengthKey(std::span<const uint8_t, 16> response_key,
                                      std::span<const uint8_t, 16> response_iv);
HeaderAeadKey ResponseHeaderPayloadKey(std::span<const uint8_t, 16> response_key,
                                       std::span<const uint8_t, 16> response_iv);

// ============================================================================
// AES-128-GCM
// ============================================================================

bool AES128GCMDecryptTo(
    const uint8_t* key, const uint8_t* nonce, size_t nonce_len,
    const uint8_t* ciphertext, size_t len,
    const uint8_t* aad, size_t aad_len,
    uint8_t* plaintext, size_t plaintext_capacity,
    size_t& plaintext_len);

bool AES128GCMEncrypt(
    const uint8_t* key, const uint8_t* nonce,
    const uint8_t* aad, size_t aad_len,
    const uint8_t* plaintext, size_t len,
    uint8_t* ciphertext, uint8_t* tag);

// ============================================================================
// 校验和
// ============================================================================

uint32_t CRC32(const uint8_t* data, size_t len);
uint32_t FNV1a32(const uint8_t* data, size_t len);

// ============================================================================
// AuthID 生成（客户端使用）
// ============================================================================

// AES-128 encrypt schedule of an account's AuthID key, expanded once when the
// outbound account is prepared; requests only borrow it.
[[nodiscard]] AES_KEY ExpandAuthIDEncryptKey(const std::array<uint8_t, 16>& auth_key);
void GenerateAuthID(const AES_KEY& auth_id_key, int64_t timestamp, uint8_t* out_auth_id);

}  // namespace vmess
