#pragma once

// ============================================================================
// validator.hpp — Trojan 用户管理
//
// 职责（协议特有）：
//   - 认证：password_hash → 全局 UserStore credential
//   - 验证：SHA224 哈希比对
//   - 按 tag 独立管理（面板多入站场景）
//
// 通用能力（委托给在线追踪实现）：
//   - 在线追踪：OnUserConnected / OnUserDisconnected / GetOnlineDevices 等
// ============================================================================

#include "acppnode/app/proxyman/inbound/user_store.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace acpp {
struct OnlineDevice;
}  // namespace acpp

namespace acpp::trojan {

// ============================================================================
// Trojan 用户管理器
// ============================================================================
class Validator {
public:
    Validator() = default;
    ~Validator() = default;

    Validator(const Validator&) = delete;
    Validator& operator=(const Validator&) = delete;
    Validator(Validator&&) noexcept = default;
    Validator& operator=(Validator&&) noexcept = default;

    // ── 认证与查找 ───────────────────────────────────────────────────────────

    std::shared_ptr<const proxyman::inbound::UserStore::TrojanCredential>
    FindUser(std::string_view tag, std::string_view hash) const;

    size_t Size() const;
    size_t SizeForTag(std::string_view tag) const;

    // ── 在线追踪 ─────────────────────────────────────────────────────────────


};

}  // namespace acpp::trojan
