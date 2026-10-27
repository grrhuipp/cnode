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
#include "acppnode/common/sharded_user_stats.hpp"

#include <memory>
#include <string_view>

namespace acpp::trojan {

class Validator : public UserOnlineTracker {
public:
    using UserOnlineTracker::UserOnlineTracker;

    [[nodiscard]] std::shared_ptr<const proxyman::inbound::UserStore::TrojanCredential>
    FindUser(std::string_view tag, std::string_view hash) const;
};
}  // namespace acpp::trojan
