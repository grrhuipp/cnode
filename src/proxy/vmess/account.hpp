#pragma once

// ============================================================================
// account.hpp — VMess MemoryAccount 定义
//
// 职责：
//   - VMess 账户身份数据和预计算密钥
//   - 仅做冷路径账户构造，不包含验证器或查找逻辑
// ============================================================================

#include "acppnode/common/user_profile.hpp"
#include "acppnode/common/unsafe.hpp"
#include <array>
#include <cstdint>
#include <optional>
#include <string>

namespace acpp::vmess {

struct MemoryAccount {
    std::string             uuid;
    std::array<uint8_t, 16> uuid_bytes{};
    std::array<uint8_t, 16> cmd_key{};
    std::array<uint8_t, 16> auth_key{};
    ::acpp::UserProfile profile;

    ~MemoryAccount() noexcept {
        ::acpp::SecureZeroMemory(uuid_bytes.data(), uuid_bytes.size());
        ::acpp::SecureZeroMemory(cmd_key.data(), cmd_key.size());
        ::acpp::SecureZeroMemory(auth_key.data(), auth_key.size());
    }
    static std::optional<MemoryAccount> FromUUID(
        const std::string& uuid_str,
        int64_t user_id = 0,
        const std::string& email = "",
        uint64_t speed_limit = 0,
        uint32_t device_limit = 0);
};

}  // namespace acpp::vmess
