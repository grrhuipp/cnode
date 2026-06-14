#include "acppnode/proxy/trojan/validator.hpp"

#include "acppnode/common/allocator.hpp"
#include "acppnode/common/sharded_user_stats.hpp"
#include "acppnode/common/string_hash.hpp"

namespace acpp::trojan {

struct Validator::Impl {
    using UserMap = memory::ThreadLocalUnorderedMap<std::string,
                                                    TrojanUserInfo,
                                                    TransparentStringHash,
                                                    TransparentStringEq>;
    memory::ThreadLocalUnorderedMap<std::string,
                                    UserMap,
                                    TransparentStringHash,
                                    TransparentStringEq> users_by_tag;
    UserOnlineTracker stats;
};

Validator::Validator()
    : impl_(std::make_unique<Impl>()) {
}

Validator::~Validator() = default;
Validator::Validator(Validator&&) noexcept = default;
Validator& Validator::operator=(Validator&&) noexcept = default;

void Validator::UpdateUsersForTag(const std::string& tag, const std::vector<TrojanUserInfo>& new_users) {
    // Per-worker: no lock needed
    auto& tag_users = impl_->users_by_tag[tag];
    tag_users.reserve(new_users.size());

    // 构建新用户哈希集合
    memory::ThreadLocalUnorderedSet<std::string,
                                    TransparentStringHash,
                                    TransparentStringEq> new_hashes;
    new_hashes.reserve(new_users.size());
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

void Validator::AddUsersForTag(const std::string& tag,
                                       const std::vector<TrojanUserInfo>& users) {
    auto& tag_users = impl_->users_by_tag[tag];
    tag_users.reserve(tag_users.size() + users.size());
    for (const auto& user : users) {
        tag_users[user.password_hash] = user;
    }
}

void Validator::RemoveUsersForTag(const std::string& tag,
                                          const std::vector<TrojanUserInfo>& users) {
    auto it = impl_->users_by_tag.find(tag);
    if (it == impl_->users_by_tag.end()) {
        return;
    }
    for (const auto& user : users) {
        it->second.erase(user.password_hash);
    }
    if (it->second.empty()) {
        impl_->users_by_tag.erase(it);
    }
}

bool Validator::Validate(std::string_view tag, std::string_view hash) const {
    auto tag_it = impl_->users_by_tag.find(tag);
    if (tag_it != impl_->users_by_tag.end()) {
        if (tag_it->second.find(hash) != tag_it->second.end()) {
            return true;
        }
    }
    return false;
}

std::optional<TrojanUserInfo> Validator::FindUser(std::string_view tag, std::string_view hash) const {
    auto tag_it = impl_->users_by_tag.find(tag);
    if (tag_it != impl_->users_by_tag.end()) {
        auto it = tag_it->second.find(hash);
        if (it != tag_it->second.end()) {
            return it->second;
        }
    }
    return std::nullopt;
}

size_t Validator::Size() const {
    size_t total = 0;
    for (const auto& [tag, users] : impl_->users_by_tag) {
        total += users.size();
    }
    return total;
}

size_t Validator::SizeForTag(std::string_view tag) const {
    auto it = impl_->users_by_tag.find(tag);
    return it != impl_->users_by_tag.end() ? it->second.size() : 0;
}

void Validator::OnUserConnected(std::string_view tag,
                                uint64_t user_id,
                                std::string_view client_ip) {
    impl_->stats.OnUserConnected(tag, user_id, client_ip);
}

void Validator::OnUserDisconnected(std::string_view tag,
                                   uint64_t user_id,
                                   std::string_view client_ip) {
    impl_->stats.OnUserDisconnected(tag, user_id, client_ip);
}

bool Validator::CanAcceptDevice(std::string_view tag,
                                uint64_t user_id,
                                std::string_view client_ip,
                                uint32_t device_limit) const {
    return impl_->stats.CanAcceptDevice(tag, user_id, client_ip, device_limit);
}

size_t Validator::OnlineDeviceCount(std::string_view tag,
                                    uint64_t user_id) const {
    return impl_->stats.OnlineDeviceCount(tag, user_id);
}

std::vector<OnlineDevice> Validator::GetOnlineDevices(std::string_view tag) const {
    return impl_->stats.GetOnlineDevices(tag);
}

}  // namespace acpp::trojan
