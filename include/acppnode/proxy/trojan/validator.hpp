#pragma once

// ============================================================================
// validator.hpp — Trojan 用户管理
//
// 职责（协议特有）：
//   - 用户存储：password_hash → TrojanUserInfo
//   - 验证：SHA224 哈希比对
//   - 按 tag 独立管理（面板多入站场景）
//
// 通用能力（委托给在线追踪实现）：
//   - 在线追踪：OnUserConnected / OnUserDisconnected / GetOnlineDevices 等
// ============================================================================

#include "acppnode/proxy/trojan/user_info.hpp"

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

[[nodiscard]] std::string HashPassword(const std::string& password);

// ============================================================================
// Trojan 用户管理器
// ============================================================================
class Validator {
public:
    Validator();
    ~Validator();

    Validator(const Validator&) = delete;
    Validator& operator=(const Validator&) = delete;
    Validator(Validator&&) noexcept;
    Validator& operator=(Validator&&) noexcept;

    // ── 用户存储 ─────────────────────────────────────────────────────────────

    // 增量更新指定 tag 的用户列表（无空窗期）
    void UpdateUsersForTag(const std::string& tag, const std::vector<TrojanUserInfo>& new_users);
    void AddUsersForTag(const std::string& tag, const std::vector<TrojanUserInfo>& users);
    void RemoveUsersForTag(const std::string& tag, const std::vector<TrojanUserInfo>& users);

    // ── 认证与查找 ───────────────────────────────────────────────────────────

    bool Validate(std::string_view tag, std::string_view hash) const;

    std::optional<TrojanUserInfo> FindUser(std::string_view tag, std::string_view hash) const;

    size_t Size() const;
    size_t SizeForTag(std::string_view tag) const;

    // ── 在线追踪 ─────────────────────────────────────────────────────────────

    void OnUserConnected(std::string_view tag,
                         uint64_t user_id,
                         std::string_view client_ip);

    void OnUserDisconnected(std::string_view tag,
                            uint64_t user_id,
                            std::string_view client_ip);

    [[nodiscard]] bool CanAcceptDevice(std::string_view tag,
                                       uint64_t user_id,
                                       std::string_view client_ip,
                                       uint32_t device_limit) const;

    [[nodiscard]] size_t OnlineDeviceCount(std::string_view tag,
                                           uint64_t user_id) const;

    [[nodiscard]] std::vector<OnlineDevice>
    GetOnlineDevices(std::string_view tag) const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace acpp::trojan
