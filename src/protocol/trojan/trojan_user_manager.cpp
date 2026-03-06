#include "acppnode/protocol/trojan/trojan_user_manager.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/common/unsafe.hpp"
#include <openssl/sha.h>
#include <unordered_set>

namespace acpp::trojan {

// 静态十六进制查找表，避免 ostringstream 开销
static const char HEX_CHARS[] = "0123456789abcdef";

std::string TrojanUserManager::HashPassword(const std::string& password) {
    unsigned char hash[SHA224_DIGEST_LENGTH];
    SHA224(unsafe::ptr_cast<const unsigned char>(password.data()),
           password.size(), hash);

    // 直接构造字符串，比 ostringstream 快 10 倍以上
    std::string result;
    result.reserve(SHA224_DIGEST_LENGTH * 2);

    for (int i = 0; i < SHA224_DIGEST_LENGTH; ++i) {
        result.push_back(HEX_CHARS[hash[i] >> 4]);
        result.push_back(HEX_CHARS[hash[i] & 0x0F]);
    }

    return result;
}

void TrojanUserManager::AddUser(const std::string& password,
                                const std::string& email,
                                int64_t user_id,
                                uint64_t speed_limit) {
    // Per-worker: no lock needed
    auto hash = HashPassword(password);
    global_users_[hash] = TrojanUserInfo{hash, email, user_id, speed_limit};
    // 安全加固：不记录 hash 值，防止暴力破解
    LOG_DEBUG("Trojan user registered: email={} speed_limit={}",
              email, speed_limit);
}

void TrojanUserManager::AddUserByHash(const std::string& hash,
                                      const std::string& email,
                                      int64_t user_id,
                                      uint64_t speed_limit) {
    // Per-worker: no lock needed
    global_users_[hash] = TrojanUserInfo{hash, email, user_id, speed_limit};
}

void TrojanUserManager::RemoveUser(const std::string& password) {
    // Per-worker: no lock needed
    global_users_.erase(HashPassword(password));
}

void TrojanUserManager::RemoveUserByHash(const std::string& hash) {
    // Per-worker: no lock needed
    global_users_.erase(hash);
}

void TrojanUserManager::Clear() {
    // Per-worker: no lock needed
    users_by_tag_.clear();
    global_users_.clear();
}

void TrojanUserManager::UpdateSharedUsersForTag(const std::string& tag, std::vector<TrojanUserInfo>&& users) {
    TrojanUserManager::SharedStore().UpdateTag(tag, std::move(users));
}

void TrojanUserManager::UpdateUsersForTag(const std::string& tag, const std::vector<TrojanUserInfo>& new_users) {
    if (use_shared_store_) {
        // 共享存储模式：用户数据由 SharedStore 管理
        return;
    }

    // 本地存储模式（旧行为）
    // Per-worker: no lock needed
    auto& tag_users = users_by_tag_[tag];

    // 构建新用户哈希集合
    std::unordered_set<std::string> new_hashes;
    for (const auto& user : new_users) {
        new_hashes.insert(user.password_hash);
    }

    // 删除不在新列表中的用户
    for (auto it = tag_users.begin(); it != tag_users.end(); ) {
        if (new_hashes.find(it->first) == new_hashes.end()) {
            it = tag_users.erase(it);
        } else {
            ++it;
        }
    }

    // 添加或更新用户
    for (const auto& user : new_users) {
        tag_users[user.password_hash] = user;
    }
}

bool TrojanUserManager::Validate(const std::string& hash) const {
    if (use_shared_store_) {
        return TrojanUserManager::SharedStore().Find(hash) != nullptr;
    }

    // 使用恒定时间比较防止时序攻击
    bool found = false;

    for (const auto& [tag, users] : users_by_tag_) {
        for (const auto& [h, _] : users) {
            found |= unsafe::constant_time_string_compare(h, hash);
        }
    }
    for (const auto& [h, _] : global_users_) {
        found |= unsafe::constant_time_string_compare(h, hash);
    }
    return found;
}

bool TrojanUserManager::Validate(const std::string& tag, const std::string& hash) const {
    if (use_shared_store_) {
        // 共享存储模式必须严格按 tag 隔离，避免跨入站认证
        return TrojanUserManager::SharedStore().Find(tag, hash) != nullptr;
    }

    auto tag_it = users_by_tag_.find(tag);
    if (tag_it != users_by_tag_.end()) {
        if (tag_it->second.find(hash) != tag_it->second.end()) {
            return true;
        }
    }
    return global_users_.find(hash) != global_users_.end();
}

std::optional<TrojanUserInfo> TrojanUserManager::FindUser(const std::string& hash) const {
    if (use_shared_store_) {
        auto user = TrojanUserManager::SharedStore().Find(hash);
        if (user) return *user;
        return std::nullopt;
    }

    for (const auto& [tag, users] : users_by_tag_) {
        auto it = users.find(hash);
        if (it != users.end()) {
            return it->second;
        }
    }
    auto it = global_users_.find(hash);
    if (it != global_users_.end()) {
        return it->second;
    }
    return std::nullopt;
}

std::optional<TrojanUserInfo> TrojanUserManager::FindUser(const std::string& tag, const std::string& hash) const {
    if (use_shared_store_) {
        auto user = TrojanUserManager::SharedStore().Find(tag, hash);
        if (user) return *user;
        return std::nullopt;
    }

    auto tag_it = users_by_tag_.find(tag);
    if (tag_it != users_by_tag_.end()) {
        auto it = tag_it->second.find(hash);
        if (it != tag_it->second.end()) {
            return it->second;
        }
    }
    auto it = global_users_.find(hash);
    if (it != global_users_.end()) {
        return it->second;
    }
    return std::nullopt;
}

std::string TrojanUserManager::FindEmail(const std::string& hash) const {
    auto user = FindUser(hash);
    return user ? user->email : "";
}

size_t TrojanUserManager::Size() const {
    if (use_shared_store_) {
        return TrojanUserManager::SharedStore().Size();
    }

    size_t total = global_users_.size();
    for (const auto& [tag, users] : users_by_tag_) {
        total += users.size();
    }
    return total;
}

}  // namespace acpp::trojan
