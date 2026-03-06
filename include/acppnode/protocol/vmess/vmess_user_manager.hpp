#pragma once

// ============================================================================
// vmess_user_manager.hpp — VMess 用户存储与在线追踪
//
// 职责（协议特有）：
//   - VMessUser：UUID、预计算密钥、限速
//   - 用户存储（支持全局共享 RCU 模式）
//   - 热点用户缓存（LRU，5 分钟窗口）
//
// 通用能力（委托给 ShardedUserStats<64>）：
//   - 在线用户追踪（64 分片 spinlock）
// ============================================================================

#include "acppnode/protocol/vmess/vmess_cipher.hpp"
#include "acppnode/app/shared_user_store.hpp"
#include "acppnode/common/sharded_user_stats.hpp"
#include "acppnode/common/spinlock.hpp"
#include "acppnode/infra/log.hpp"

#include <array>
#include <vector>
#include <string>
#include <optional>
#include <memory>
#include <shared_mutex>
#include <unordered_map>
#include <unordered_set>
#include <atomic>
#include <algorithm>
#include <cstdint>

namespace acpp {
namespace vmess {

// ============================================================================
// VMessUser — 单个用户的身份与密钥数据
// ============================================================================
struct VMessUser {
    std::string             uuid;            // UUID 字符串
    std::array<uint8_t, 16> uuid_bytes;      // UUID 字节
    std::array<uint8_t, 16> cmd_key;         // CMD Key = MD5(UUID + magic)
    std::array<uint8_t, 16> auth_key;        // Auth Key = KDF16(cmd_key, "AES Auth ID Encryption")
    int64_t                 user_id     = 0;
    std::string             email;
    uint64_t                speed_limit = 0; // bytes/s，0=不限速

    // 预计算的 AES 解密密钥（避免每次调用 AES_set_decrypt_key）
    CachedAESKey cached_auth_aes_key;

    // SharedUserStore<T> 要求的 key 提取方法
    std::string_view key() const { return uuid; }

    // 从 UUID 字符串创建用户（包含完整密钥派生）
    static std::optional<VMessUser> FromUUID(const std::string& uuid_str,
                                              int64_t user_id = 0,
                                              const std::string& email = "",
                                              uint64_t speed_limit = 0);
};

// ============================================================================
// VMessUserManager — 用户管理器
//
// 线程模型：
//   - 读操作（FindByAuthID 等）：多线程并发，使用 shared_mutex 或 RCU 快照
//   - 写操作（UpdateUsersForTag 等）：序列化（write_mutex_）
//   - 在线追踪 / 流量 / ban：分片 spinlock，独立于读写锁
// ============================================================================
class VMessUserManager {
public:
    VMessUserManager() : use_shared_store_(false) {}
    explicit VMessUserManager(bool use_shared_store) : use_shared_store_(use_shared_store) {}

    // ── 用户存储 ─────────────────────────────────────────────────────────────

    // 按 tag 批量更新用户（不同 tag 独立存储）
    void UpdateUsersForTag(const std::string& tag, const std::vector<VMessUser>& users);

    // 全局共享存储（RCU，所有 Worker 共享同一份数据）
    static SharedUserStore<VMessUser>& SharedStore() {
        static SharedUserStore<VMessUser> store;
        return store;
    }

    // 更新全局共享存储（所有 Worker 共享，RCU 模式）
    static void UpdateSharedUsersForTag(const std::string& tag, std::vector<VMessUser>&& users);

    void EnableSharedStore() { use_shared_store_ = true; }

    void ClearTag(const std::string& tag);
    void Clear();

    size_t Size() const;
    size_t SizeForTag(const std::string& tag) const;

    // 通过 AuthID 查找用户（AEAD 模式，搜索所有 tag）
    const VMessUser* FindByAuthID(const uint8_t* auth_id, int64_t& out_timestamp) const;

    // 通过 AuthID 查找用户，限定 tag（优化：O(N_tag) 而非 O(N_total)）
    const VMessUser* FindByAuthIDForTag(const std::string& tag,
                                        const uint8_t* auth_id,
                                        int64_t& out_timestamp) const;

    std::vector<const VMessUser*> GetAllUsers() const;

    // ── 在线追踪 ─────────────────────────────────────────────────────────────

    void OnUserConnected(const std::string& tag, uint64_t user_id) {
        stats_.OnUserConnected(tag, user_id);
    }

    void OnUserDisconnected(const std::string& tag, uint64_t user_id) {
        stats_.OnUserDisconnected(tag, user_id);
    }

    [[nodiscard]] std::vector<int64_t> GetOnlineUserIds(const std::string& tag) const {
        return stats_.GetOnlineUserIds(tag);
    }

private:
    // ── 用户存储 ─────────────────────────────────────────────────────────────

    bool use_shared_store_ = false;
    mutable std::shared_mutex mutex_;
    std::unordered_map<std::string, std::unordered_map<std::string, VMessUser>> users_by_tag_;

    // ── 热点用户缓存（LRU，5 分钟窗口）──────────────────────────────────────

    static constexpr int64_t kHotCacheWindowSeconds = 300;

    struct alignas(64) HotUserCache {
        mutable acpp::SpinLock lock;

        // 缓存条目：持有 shared_ptr 防止 RCU 快照更新后用户对象被释放
        struct Entry {
            std::shared_ptr<const VMessUser> ref;  // 共享存储模式下保持引用
            int64_t timestamp;
        };
        std::unordered_map<const VMessUser*, Entry> entries;
        std::vector<const VMessUser*>               active_order;

        // ref: 共享存储模式传入 shared_ptr 保持用户对象存活；
        //      本地存储模式传空（生命周期由 users_by_tag_ 管理）
        void Touch(const VMessUser* user, int64_t now,
                   std::shared_ptr<const VMessUser> ref = nullptr) {
            auto it = entries.find(user);
            if (it != entries.end()) {
                it->second.timestamp = now;
                auto pos = std::find(active_order.begin(), active_order.end(), user);
                if (pos != active_order.end() && pos != active_order.begin()) {
                    active_order.erase(pos);
                    active_order.insert(active_order.begin(), user);
                }
            } else {
                entries[user] = {std::move(ref), now};
                active_order.insert(active_order.begin(), user);
            }
        }

        void Cleanup(int64_t now) {
            constexpr int64_t window = 300;
            for (auto it = entries.begin(); it != entries.end(); ) {
                if (it->second.timestamp + window < now) {
                    auto pos = std::find(active_order.begin(), active_order.end(), it->first);
                    if (pos != active_order.end()) active_order.erase(pos);
                    it = entries.erase(it);
                } else {
                    ++it;
                }
            }
        }

        void Clear() {
            entries.clear();
            active_order.clear();
        }

        size_t Size() const { return entries.size(); }
        const std::vector<const VMessUser*>& GetActiveUsers() const { return active_order; }

        void UpdateTime(const VMessUser* user, int64_t now) {
            auto it = entries.find(user);
            if (it != entries.end()) it->second.timestamp = now;
        }
    };

    mutable HotUserCache         hot_cache_;
    mutable std::atomic<int64_t> last_hot_cache_cleanup_{0};

    ShardedUserStats<64> stats_;
};

}  // namespace vmess
}  // namespace acpp
