#pragma once

// ============================================================================
// trojan_user_manager.hpp — Trojan 用户管理
//
// 职责（协议特有）：
//   - 用户存储：password_hash → TrojanUserInfo
//   - 验证：SHA224 哈希比对
//   - 按 tag 独立管理（面板多入站场景）
//
// 通用能力（委托给 ShardedUserStats<16>）：
//   - 在线追踪：OnUserConnected / OnUserDisconnected / GetOnlineUserIds 等
// ============================================================================

#include "acppnode/common.hpp"
#include "acppnode/app/shared_user_store.hpp"
#include "acppnode/common/sharded_user_stats.hpp"

#include <shared_mutex>

namespace acpp::trojan {

// ============================================================================
// Trojan 用户信息
// ============================================================================
struct TrojanUserInfo {
    std::string password_hash;  // SHA224 哈希（用于存储和查找）
    std::string email;
    int64_t user_id = 0;
    uint64_t speed_limit = 0;  // bytes/s, 0 = 不限速

    // SharedUserStore<T> 要求的 key 提取方法
    std::string_view key() const { return password_hash; }
};

// ============================================================================
// Trojan 用户管理器
// ============================================================================
class TrojanUserManager {
public:
    TrojanUserManager() : use_shared_store_(false) {}
    explicit TrojanUserManager(bool use_shared_store) : use_shared_store_(use_shared_store) {}

    // ── 用户存储 ─────────────────────────────────────────────────────────────

    // 添加用户（密码明文）
    void AddUser(const std::string& password,
                 const std::string& email = "",
                 int64_t user_id = 0,
                 uint64_t speed_limit = 0);

    // 添加用户（密码哈希）
    void AddUserByHash(const std::string& hash,
                       const std::string& email = "",
                       int64_t user_id = 0,
                       uint64_t speed_limit = 0);

    void RemoveUser(const std::string& password);
    void RemoveUserByHash(const std::string& hash);
    void Clear();

    // 增量更新指定 tag 的用户列表（无空窗期）
    void UpdateUsersForTag(const std::string& tag, const std::vector<TrojanUserInfo>& new_users);

    // 全局共享存储（RCU，所有 Worker 共享同一份数据）
    static SharedUserStore<TrojanUserInfo>& SharedStore() {
        static SharedUserStore<TrojanUserInfo> store;
        return store;
    }

    // 更新全局共享存储
    static void UpdateSharedUsersForTag(const std::string& tag, std::vector<TrojanUserInfo>&& users);

    void EnableSharedStore() { use_shared_store_ = true; }

    // ── 认证与查找 ───────────────────────────────────────────────────────────

    bool Validate(const std::string& hash) const;
    bool Validate(const std::string& tag, const std::string& hash) const;

    std::optional<TrojanUserInfo> FindUser(const std::string& hash) const;
    std::optional<TrojanUserInfo> FindUser(const std::string& tag, const std::string& hash) const;

    std::string FindEmail(const std::string& hash) const;

    size_t Size() const;

    // 计算密码哈希（SHA224 十六进制）
    static std::string HashPassword(const std::string& password);

    // 将哈希转换为 user_id（用于分片路由）
    static uint64_t HashToUserId(const std::string& hash) {
        uint64_t id = 0;
        for (size_t i = 0; i < std::min(hash.size(), size_t(16)); ++i)
            id = id * 31 + static_cast<uint8_t>(hash[i]);
        return id;
    }

    // ── 在线追踪 ─────────────────────────────────────────────────────────────

    // 连接建立：hash → 内部 user_id（返回值供断开时使用）
    uint64_t OnUserConnected(const std::string& tag, const std::string& hash) {
        uint64_t user_id = HashToUserId(hash);
        stats_.OnUserConnected(tag, user_id);
        return user_id;
    }

    void OnUserDisconnected(const std::string& tag, uint64_t user_id) {
        stats_.OnUserDisconnected(tag, user_id);
    }

    [[nodiscard]] std::vector<int64_t> GetOnlineUserIds(const std::string& tag) const {
        return stats_.GetOnlineUserIds(tag);
    }

private:
    bool use_shared_store_ = false;
    mutable std::shared_mutex mutex_;

    // 按 tag 管理：tag → (hash → user info)
    std::unordered_map<std::string, std::unordered_map<std::string, TrojanUserInfo>> users_by_tag_;
    // 兼容旧接口的全局用户表
    std::unordered_map<std::string, TrojanUserInfo> global_users_;

    ShardedUserStats<16> stats_;
};

}  // namespace acpp::trojan
