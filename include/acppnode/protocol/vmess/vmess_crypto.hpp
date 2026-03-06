#pragma once

// ============================================================================
// vmess_crypto.hpp — VMess 密码学原语
//
// 职责：底层加密函数、密钥派生（KDF）、哈希、随机数生成。
// 不包含任何协议结构体或用户管理逻辑。
// ============================================================================

#include "acppnode/common.hpp"
#include <array>
#include <vector>
#include <string>
#include <string_view>
#include <optional>
#include <cstdint>

namespace acpp {
namespace vmess {

// ============================================================================
// UUID 解析
// ============================================================================

// 解析 UUID 字符串（带连字符）为字节数组
std::optional<std::array<uint8_t, 16>> ParseUUID(const std::string& uuid_str);

// ============================================================================
// 哈希函数
// ============================================================================

std::array<uint8_t, 16> MD5Hash(const uint8_t* data, size_t len);
std::array<uint8_t, 32> SHA256Hash(const uint8_t* data, size_t len);

// SHA256Sum (SHA256Hash 的别名)
inline std::array<uint8_t, 32> SHA256Sum(const uint8_t* data, size_t len) {
    return SHA256Hash(data, len);
}

std::array<uint8_t, 16> HMAC_MD5(const uint8_t* key, size_t key_len,
                                  const uint8_t* data, size_t data_len);

// ============================================================================
// VMess AEAD KDF（嵌套 HMAC-SHA256）
// ============================================================================

void KDF(const uint8_t* key, size_t key_len,
         std::span<const std::string_view> path,
         uint8_t* out, size_t out_len);

// KDF16 — 返回 16 字节派生密钥
std::array<uint8_t, 16> KDF16(const uint8_t* key, size_t key_len,
                               std::span<const std::string_view> path);

// ============================================================================
// AES-128-GCM
// ============================================================================

std::optional<std::vector<uint8_t>> AES128GCMDecrypt(
    const uint8_t* key, const uint8_t* nonce, size_t nonce_len,
    const uint8_t* ciphertext, size_t len,
    const uint8_t* aad, size_t aad_len);

std::vector<uint8_t> AES128GCMEncrypt(
    const uint8_t* key, const uint8_t* nonce, size_t nonce_len,
    const uint8_t* plaintext, size_t len,
    const uint8_t* aad, size_t aad_len);

// 带输出参数的重载（避免堆分配，用于热路径）
bool AES128GCMEncrypt(
    const uint8_t* key, const uint8_t* nonce,
    const uint8_t* aad, size_t aad_len,
    const uint8_t* plaintext, size_t len,
    uint8_t* ciphertext, uint8_t* tag);

// ============================================================================
// AES-128-ECB（用于 AuthID 生成与验证）
// ============================================================================

void AES128ECBEncrypt(const uint8_t* key, const uint8_t* plaintext, uint8_t* ciphertext);
void AES128ECBDecrypt(const uint8_t* key, const uint8_t* ciphertext, uint8_t* plaintext);

// ============================================================================
// 校验和
// ============================================================================

uint32_t CRC32(const uint8_t* data, size_t len);
uint32_t FNV1a32(const uint8_t* data, size_t len);

// ============================================================================
// AuthID 生成（客户端使用）
// ============================================================================

void GenerateAuthID(const uint8_t* auth_key, int64_t timestamp, uint8_t* out_auth_id);

// ============================================================================
// 随机数
// ============================================================================

void RandomBytes(uint8_t* buf, size_t len);

// ============================================================================
// SHAKE128（用于 chunk masking）
// ============================================================================

void SHAKE128(const uint8_t* input, size_t input_len,
              uint8_t* output, size_t output_len);

// ============================================================================
// CachedAESKey — 缓存的 AES-128 ECB 解密密钥（16 字节原始密钥）
// ============================================================================
struct CachedAESKey {
    uint8_t key[16] = {};

    void InitDecryptKey(const uint8_t* k);
    void ECBDecrypt(const uint8_t* ciphertext, uint8_t* plaintext) const;
};

}  // namespace vmess
}  // namespace acpp
