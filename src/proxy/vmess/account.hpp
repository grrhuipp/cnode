#pragma once

// ============================================================================
// account.hpp — VMess MemoryAccount 定义
//
// 职责：
//   - VMess 账户身份数据和预计算密钥
//   - 仅做冷路径账户构造，不包含验证器或查找逻辑
// ============================================================================

#include "acppnode/common/user_profile.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <string>

namespace acpp::vmess {

// 缓存的 AES-128 ECB 解密 key。公开在 MemoryAccount 中作为预计算身份数据，
// 具体 AES 实现留在 VMess 私有 crypto helper。
struct CachedAESKey {
    uint8_t key[16] = {};

    void InitDecryptKey(const uint8_t* k);
    void ECBDecrypt(const uint8_t* ciphertext, uint8_t* plaintext) const;
};

struct MemoryAccount {
    std::string             uuid;
    std::array<uint8_t, 16> uuid_bytes;
    std::array<uint8_t, 16> cmd_key;
    std::array<uint8_t, 16> auth_key;
    CachedAESKey cached_auth_aes_key;
    ::acpp::UserProfile profile;

    static std::optional<MemoryAccount> FromUUID(
        const std::string& uuid_str,
        int64_t user_id = 0,
        const std::string& email = "",
        uint64_t speed_limit = 0,
        uint32_t device_limit = 0);
};

}  // namespace acpp::vmess
