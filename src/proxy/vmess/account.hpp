#pragma once

// ============================================================================
// account.hpp — VMess MemoryAccount 定义
//
// 职责：
//   - VMess 账户身份数据和预计算密钥
//   - 仅做冷路径账户构造，不包含验证器或查找逻辑
// ============================================================================

#include "common/unsafe.hpp"
#include <array>
#include <cstdint>
#include <optional>
#include <string_view>

namespace vmess {

struct MemoryAccount {
    std::array<uint8_t, 16> uuid_bytes{};
    std::array<uint8_t, 16> cmd_key{};
    std::array<uint8_t, 16> auth_key{};

    ~MemoryAccount() noexcept {
        ::SecureZeroMemory(uuid_bytes.data(), uuid_bytes.size());
        ::SecureZeroMemory(cmd_key.data(), cmd_key.size());
        ::SecureZeroMemory(auth_key.data(), auth_key.size());
    }
    static std::optional<MemoryAccount> FromUUID(std::string_view uuid_str);
};

}  // namespace vmess
