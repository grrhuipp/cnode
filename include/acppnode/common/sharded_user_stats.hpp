#pragma once

// ============================================================================
// sharded_user_stats.hpp — 分片在线用户追踪
//
// 从 VMessUserManager / TrojanUserManager 中提取的公共逻辑。
// 协议特有内容（用户存储、认证、HotCache、IP 封禁）各自保留在协议 manager 中。
//
// 模板参数：
//   NShards — 分片数量（推荐 2 的幂，VMess 用 64，Trojan 用 16）
//
// 所有分片使用 alignas(64) 避免伪共享。
// ============================================================================

#include "acppnode/common/spinlock.hpp"

#include <array>
#include <atomic>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace acpp {

template<size_t NShards>
class ShardedUserStats {
public:
    // ========================================================================
    // 在线用户追踪
    // key: tag → {user_id → 连接计数}
    // ========================================================================

    void OnUserConnected(const std::string& tag, uint64_t user_id) {
        auto& shard = GetOnlineShard(user_id);
        shard.lock.Lock();
        shard.connections[tag][user_id]++;
        shard.lock.Unlock();
        total_connections_.fetch_add(1, std::memory_order_relaxed);
    }

    void OnUserDisconnected(const std::string& tag, uint64_t user_id) {
        auto& shard = GetOnlineShard(user_id);
        shard.lock.Lock();
        auto tag_it = shard.connections.find(tag);
        if (tag_it != shard.connections.end()) {
            auto it = tag_it->second.find(user_id);
            if (it != tag_it->second.end() && --it->second == 0)
                tag_it->second.erase(it);
        }
        shard.lock.Unlock();
        total_connections_.fetch_sub(1, std::memory_order_relaxed);
    }

    // 指定 tag 的去重在线用户数
    size_t OnlineUserCount(const std::string& tag) const {
        std::unordered_set<uint64_t> unique_users;
        for (const auto& shard : online_shards_) {
            shard.lock.Lock();
            if (auto it = shard.connections.find(tag); it != shard.connections.end())
                for (const auto& [uid, _] : it->second) unique_users.insert(uid);
            shard.lock.Unlock();
        }
        return unique_users.size();
    }

    // 全局去重在线用户数（跨所有 tag）
    size_t OnlineUserCount() const {
        std::unordered_set<uint64_t> unique_users;
        for (const auto& shard : online_shards_) {
            shard.lock.Lock();
            for (const auto& [tag, users] : shard.connections)
                for (const auto& [uid, _] : users) unique_users.insert(uid);
            shard.lock.Unlock();
        }
        return unique_users.size();
    }

    // 指定 tag 的活跃连接数（含多连接用户）
    size_t ActiveConnectionCount(const std::string& tag) const {
        size_t total = 0;
        for (const auto& shard : online_shards_) {
            shard.lock.Lock();
            if (auto it = shard.connections.find(tag); it != shard.connections.end())
                for (const auto& [_, count] : it->second) total += count;
            shard.lock.Unlock();
        }
        return total;
    }

    // 全局活跃连接数（原子计数，O(1)）
    size_t ActiveConnectionCount() const {
        return total_connections_.load(std::memory_order_relaxed);
    }

    // 指定 tag 有连接的在线用户 ID 列表
    std::vector<int64_t> GetOnlineUserIds(const std::string& tag) const {
        std::vector<int64_t> result;
        std::unordered_set<uint64_t> seen;
        for (const auto& shard : online_shards_) {
            shard.lock.Lock();
            if (auto it = shard.connections.find(tag); it != shard.connections.end())
                for (const auto& [uid, count] : it->second)
                    if (count > 0 && seen.insert(uid).second)
                        result.push_back(static_cast<int64_t>(uid));
            shard.lock.Unlock();
        }
        return result;
    }

private:
    struct alignas(64) OnlineShard {
        mutable SpinLock lock;
        std::unordered_map<std::string, std::unordered_map<uint64_t, uint32_t>> connections;
    };

    mutable std::array<OnlineShard, NShards> online_shards_;
    std::atomic<size_t> total_connections_{0};

    OnlineShard& GetOnlineShard(uint64_t user_id) const {
        return online_shards_[user_id % NShards];
    }
};

}  // namespace acpp
