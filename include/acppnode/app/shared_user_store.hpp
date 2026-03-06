#pragma once

// ============================================================================
// SharedUserStore - 共享用户存储（内存优化）
//
// 问题：原架构中每个 Worker 都持有完整的用户副本
//       8 Workers × 10万用户 × 500B = 400MB
//
// 优化：用户数据全局共享，每个 Worker 只持有引用
//       1 × 10万用户 × 500B = 50MB（节省 87.5%）
//
// 架构：
//   协议 UserManager::SharedStore() (各协议自治，函数静态变量)
//     └── atomic<shared_ptr<Snapshot>> (RCU 模式)
//           └── UserT（协议自行定义，需提供 key() 方法）
//
// 更新策略：RCU (Read-Copy-Update)
//   - 读取：无锁，获取当前 snapshot 的 shared_ptr
//   - 更新：创建新 snapshot，原子替换，旧 snapshot 自然过期
//   - 无空窗期：旧 snapshot 在所有读者释放后才销毁
// ============================================================================

#include "acppnode/common.hpp"
#include <unordered_map>
#include <memory>
#include <vector>
#include <atomic>
#include <string>
#include <mutex>

namespace acpp {

// ============================================================================
// UserSnapshot - 用户数据快照（不可变）
// ============================================================================
template<typename UserT>
class UserSnapshot {
public:
    using UserPtr = std::shared_ptr<const UserT>;
    using UserMap = std::unordered_map<std::string, UserPtr>;
    using TagMap = std::unordered_map<std::string, std::shared_ptr<const UserMap>>;
    
    UserSnapshot() = default;
    
    // 从旧快照复制（用于增量更新）
    explicit UserSnapshot(const UserSnapshot& old) 
        : tag_users_(old.tag_users_)
        , global_index_(old.global_index_) {}
    
    // 更新指定 tag 的用户（创建新快照）
    // 要求 UserT 提供 key() -> string_view 方法
    static std::shared_ptr<UserSnapshot> UpdateTag(
        std::shared_ptr<const UserSnapshot> old,
        const std::string& tag,
        std::vector<UserT>&& users) {

        auto new_snapshot = std::make_shared<UserSnapshot>();
        if (old) new_snapshot->tag_users_ = old->tag_users_;

        auto new_user_map = std::make_shared<UserMap>();
        for (auto& user : users) {
            // 必须在 move 之前提取 key：MSVC 函数参数求值顺序为右到左，
            // 若 move 先执行，key() 返回的 string_view 指向已被移走的空字符串
            auto key = std::string(user.key());
            new_user_map->emplace(std::move(key),
                                  std::make_shared<const UserT>(std::move(user)));
        }

        new_snapshot->tag_users_[tag] = std::move(new_user_map);
        new_snapshot->RebuildGlobalIndex();
        return new_snapshot;
    }

    // 清除指定 tag（创建新快照）
    static std::shared_ptr<UserSnapshot> ClearTag(
        std::shared_ptr<const UserSnapshot> old,
        const std::string& tag) {

        auto new_snapshot = std::make_shared<UserSnapshot>();
        if (old) new_snapshot->tag_users_ = old->tag_users_;
        new_snapshot->tag_users_.erase(tag);
        new_snapshot->RebuildGlobalIndex();
        return new_snapshot;
    }
    
    // 查找用户（限定 tag）
    UserPtr Find(const std::string& tag, const std::string& key) const {
        auto tag_it = tag_users_.find(tag);
        if (tag_it == tag_users_.end() || !tag_it->second) {
            return nullptr;
        }
        auto user_it = tag_it->second->find(key);
        return user_it != tag_it->second->end() ? user_it->second : nullptr;
    }
    
    // 查找用户（全局）
    UserPtr Find(const std::string& key) const {
        if (!global_index_) return nullptr;
        auto it = global_index_->find(key);
        return it != global_index_->end() ? it->second : nullptr;
    }
    
    // 获取指定 tag 的用户 map（用于遍历）
    std::shared_ptr<const UserMap> GetTagUsers(const std::string& tag) const {
        auto it = tag_users_.find(tag);
        return (it != tag_users_.end()) ? it->second : nullptr;
    }
    
    // 获取全局索引
    std::shared_ptr<const UserMap> GetGlobalIndex() const {
        return global_index_;
    }
    
    // 用户数量
    size_t Size() const {
        return global_index_ ? global_index_->size() : 0;
    }
    
    size_t SizeForTag(const std::string& tag) const {
        auto it = tag_users_.find(tag);
        return (it != tag_users_.end() && it->second) ? it->second->size() : 0;
    }

private:
    TagMap tag_users_;
    std::shared_ptr<const UserMap> global_index_;
    
    // 重建全局索引
    void RebuildGlobalIndex() {
        auto new_index = std::make_shared<UserMap>();
        for (const auto& [tag, users] : tag_users_) {
            if (users) {
                for (const auto& [key, user] : *users) {
                    new_index->emplace(key, user);
                }
            }
        }
        global_index_ = std::move(new_index);
    }
};

// ============================================================================
// SharedUserStore - RCU 模式的共享用户存储
// ============================================================================
template<typename UserT>
class SharedUserStore {
public:
    using Snapshot = UserSnapshot<UserT>;
    using SnapshotPtr = std::shared_ptr<const Snapshot>;
    using UserPtr = typename Snapshot::UserPtr;
    
    SharedUserStore() 
        : snapshot_(std::make_shared<const Snapshot>()) {}
    
    // ========================================================================
    // 读取操作（无锁）
    // ========================================================================
    
    // 获取当前快照（用于批量操作）
    SnapshotPtr GetSnapshot() const {
        return snapshot_.load();
    }
    
    // 查找用户（限定 tag）
    UserPtr Find(const std::string& tag, const std::string& key) const {
        return GetSnapshot()->Find(tag, key);
    }
    
    // 查找用户（全局）
    UserPtr Find(const std::string& key) const {
        return GetSnapshot()->Find(key);
    }
    
    // 用户数量
    size_t Size() const {
        return GetSnapshot()->Size();
    }
    
    size_t SizeForTag(const std::string& tag) const {
        return GetSnapshot()->SizeForTag(tag);
    }
    
    // 遍历用户（回调方式，避免复制）
    template<typename Func>
    void ForEachUser(const std::string& tag, Func&& func) const {
        auto snapshot = GetSnapshot();
        auto users = snapshot->GetTagUsers(tag);
        if (users) {
            for (const auto& [key, user] : *users) {
                func(*user);
            }
        }
    }
    
    template<typename Func>
    void ForEachUser(Func&& func) const {
        auto snapshot = GetSnapshot();
        auto index = snapshot->GetGlobalIndex();
        if (index) {
            for (const auto& [key, user] : *index) {
                func(*user);
            }
        }
    }
    
    // ========================================================================
    // 更新操作（原子替换，无空窗期）
    // ========================================================================
    
    // 更新指定 tag 的用户
    void UpdateTag(const std::string& tag, std::vector<UserT>&& users) {
        std::lock_guard<std::mutex> lock(write_mutex_);
        auto old_snapshot = snapshot_.load();
        auto new_snapshot = Snapshot::UpdateTag(old_snapshot, tag, std::move(users));
        snapshot_.store(std::const_pointer_cast<const Snapshot>(new_snapshot));
    }
    
    // 清除指定 tag
    void ClearTag(const std::string& tag) {
        std::lock_guard<std::mutex> lock(write_mutex_);
        auto old_snapshot = snapshot_.load();
        auto new_snapshot = Snapshot::ClearTag(old_snapshot, tag);
        snapshot_.store(std::const_pointer_cast<const Snapshot>(new_snapshot));
    }
    
    // 清除所有用户
    void Clear() {
        std::lock_guard<std::mutex> lock(write_mutex_);
        snapshot_.store(std::make_shared<const Snapshot>());
    }

private:
    std::atomic<std::shared_ptr<const Snapshot>> snapshot_;
    std::mutex write_mutex_;  // 保护写操作的串行化
};

}  // namespace acpp
