#include "acppnode/proxy/shadowsocks/validator.hpp"

#include "acppnode/common/allocator.hpp"
#include "acppnode/common/sharded_user_stats.hpp"
#include "acppnode/common/string_hash.hpp"

#include <algorithm>
#include <span>

namespace acpp::ss {

struct Validator::Impl {
    using UserList = memory::ThreadLocalVector<SsUserInfo>;
    memory::ThreadLocalUnorderedMap<std::string,
                                    UserList,
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

void Validator::UpdateUsersForTag(const std::string& tag,
                                  const std::vector<SsUserInfo>& users) {
    auto& tag_users = impl_->users_by_tag[tag];
    tag_users.clear();
    tag_users.reserve(users.size());
    tag_users.insert(tag_users.end(), users.begin(), users.end());
}

void Validator::AddUsersForTag(const std::string& tag,
                               const std::vector<SsUserInfo>& users) {
    auto& tag_users = impl_->users_by_tag[tag];
    tag_users.reserve(tag_users.size() + users.size());

    auto same_identity = [](const SsUserInfo& a, const SsUserInfo& b) {
        if (a.user_id != 0 && b.user_id != 0) {
            return a.user_id == b.user_id;
        }
        return a.password == b.password;
    };

    for (const auto& user : users) {
        auto it = std::find_if(tag_users.begin(), tag_users.end(),
            [&](const SsUserInfo& existing) { return same_identity(existing, user); });
        if (it != tag_users.end()) {
            *it = user;
        } else {
            tag_users.push_back(user);
        }
    }
}

void Validator::RemoveUsersForTag(const std::string& tag,
                                  const std::vector<SsUserInfo>& users) {
    auto it = impl_->users_by_tag.find(tag);
    if (it == impl_->users_by_tag.end()) {
        return;
    }

    auto& tag_users = it->second;
    auto should_remove = [&](const SsUserInfo& existing) {
        return std::any_of(users.begin(), users.end(), [&](const SsUserInfo& user) {
            if (existing.user_id != 0 && user.user_id != 0) {
                return existing.user_id == user.user_id;
            }
            return existing.password == user.password;
        });
    };

    tag_users.erase(
        std::remove_if(tag_users.begin(), tag_users.end(), should_remove),
        tag_users.end());
    if (tag_users.empty()) {
        impl_->users_by_tag.erase(it);
    }
}

std::span<const SsUserInfo> Validator::FindUsersForTag(std::string_view tag) const {
    auto it = impl_->users_by_tag.find(tag);
    if (it == impl_->users_by_tag.end()) {
        return {};
    }
    return std::span<const SsUserInfo>(it->second.data(), it->second.size());
}

std::vector<SsUserInfo> Validator::GetUsersForTag(std::string_view tag) const {
    const auto users = FindUsersForTag(tag);
    return std::vector<SsUserInfo>(users.begin(), users.end());
}

std::optional<SsUserInfo> Validator::FindUserById(std::string_view tag,
                                                   int64_t user_id) const {
    const auto tag_users = FindUsersForTag(tag);
    for (const auto& user : tag_users)
        if (user.user_id == user_id) return user;
    return std::nullopt;
}

size_t Validator::Size() const {
    size_t total = 0;
    for (const auto& [tag, users] : impl_->users_by_tag) {
        (void)tag;
        total += users.size();
    }
    return total;
}

void Validator::OnUserConnected(std::string_view tag,
                                int64_t user_id,
                                std::string_view client_ip) {
    impl_->stats.OnUserConnected(tag, static_cast<uint64_t>(user_id), client_ip);
}

void Validator::OnUserDisconnected(std::string_view tag,
                                   uint64_t user_id,
                                   std::string_view client_ip) {
    impl_->stats.OnUserDisconnected(tag, user_id, client_ip);
}

bool Validator::CanAcceptDevice(std::string_view tag,
                                int64_t user_id,
                                std::string_view client_ip,
                                uint32_t device_limit) const {
    return impl_->stats.CanAcceptDevice(
        tag, static_cast<uint64_t>(user_id), client_ip, device_limit);
}

size_t Validator::OnlineDeviceCount(std::string_view tag,
                                    int64_t user_id) const {
    return impl_->stats.OnlineDeviceCount(tag, static_cast<uint64_t>(user_id));
}

std::vector<OnlineDevice> Validator::GetOnlineDevices(std::string_view tag) const {
    return impl_->stats.GetOnlineDevices(tag);
}

}  // namespace acpp::ss
