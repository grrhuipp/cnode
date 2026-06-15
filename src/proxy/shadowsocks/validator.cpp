#include "acppnode/proxy/shadowsocks/validator.hpp"

#include "acppnode/app/proxyman/inbound/prepared_config.hpp"
#include "acppnode/common/sharded_user_stats.hpp"
#include "acppnode/core/constants.hpp"

#include <algorithm>

namespace acpp::ss {

struct Validator::Impl {
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
    proxyman::inbound::UserSet set;
    set.ss_users = users;
    proxyman::inbound::UserStore::ApplyUsers(constants::protocol::kShadowsocks, tag, set);
}

void Validator::AddUsersForTag(const std::string& tag,
                               const std::vector<SsUserInfo>& users) {
    proxyman::inbound::UserSet set;
    set.ss_users = users;
    proxyman::inbound::UserStore::AddUsers(constants::protocol::kShadowsocks, tag, set);
}

void Validator::RemoveUsersForTag(const std::string& tag,
                                  const std::vector<SsUserInfo>& users) {
    proxyman::inbound::UserSet set;
    set.ss_users = users;
    proxyman::inbound::UserStore::RemoveUsers(constants::protocol::kShadowsocks, tag, set);
}

proxyman::inbound::UserStore::ShadowsocksUsersView
Validator::FindUsersForTag(std::string_view tag) const {
    return proxyman::inbound::UserStore::ShadowsocksUsers(tag);
}

std::vector<SsUserInfo> Validator::GetUsersForTag(std::string_view tag) const {
    const auto users = FindUsersForTag(tag);
    if (!users.users) {
        return {};
    }
    std::vector<SsUserInfo> result;
    result.reserve(users.users->size());
    for (const auto& credential : *users.users) {
        SsUserInfo user;
        user.password = credential.password;
        user.derived_key = credential.derived_key;
        user.cipher_type = credential.cipher_type;
        user.key_size = credential.key_size;
        user.salt_size = credential.salt_size;
        if (credential.profile) {
            user.profile = *credential.profile;
        }
        result.push_back(std::move(user));
    }
    return result;
}

std::optional<SsUserInfo> Validator::FindUserById(std::string_view tag,
                                                   int64_t user_id) const {
    auto credential = proxyman::inbound::UserStore::FindShadowsocksUserById(tag, user_id);
    if (!credential) {
        return std::nullopt;
    }
    SsUserInfo user;
    user.password = credential->password;
    user.derived_key = credential->derived_key;
    user.cipher_type = credential->cipher_type;
    user.key_size = credential->key_size;
    user.salt_size = credential->salt_size;
    if (credential->profile) {
        user.profile = *credential->profile;
    }
    return user;
}

size_t Validator::Size() const {
    return proxyman::inbound::UserStore::GetStats().shadowsocks_users;
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
