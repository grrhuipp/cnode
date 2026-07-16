#include "validator.hpp"

#include "acppnode/app/proxyman/inbound/prepared_config.hpp"
#include "acppnode/app/proxyman/inbound/user_store.hpp"
#include "acppnode/common/sharded_user_stats.hpp"
#include "acppnode/core/constants.hpp"

namespace acpp::trojan {

namespace {

std::vector<proxyman::inbound::PreparedTrojanUser>
ToPreparedUsers(const std::vector<TrojanUserInfo>& users) {
    std::vector<proxyman::inbound::PreparedTrojanUser> prepared;
    prepared.reserve(users.size());
    for (const auto& user : users) {
        prepared.push_back(proxyman::inbound::PreparedTrojanUser{
            .password_hash = user.password_hash,
            .profile = user.profile,
        });
    }
    return prepared;
}

}  // namespace

struct Validator::Impl {
    UserOnlineTracker stats;
};

Validator::Validator()
    : impl_(std::make_unique<Impl>()) {
}

Validator::~Validator() = default;
Validator::Validator(Validator&&) noexcept = default;
Validator& Validator::operator=(Validator&&) noexcept = default;

void Validator::ApplyUsers(std::string_view tag, const std::vector<TrojanUserInfo>& users) {
    proxyman::inbound::UserSet set{ToPreparedUsers(users)};
    proxyman::inbound::UserStore::ApplyUsers(tag, set);
}

void Validator::AddUsers(std::string_view tag,
                         const std::vector<TrojanUserInfo>& users) {
    proxyman::inbound::UserSet set{ToPreparedUsers(users)};
    proxyman::inbound::UserStore::AddUsers(tag, set);
}

void Validator::RemoveUsers(std::string_view tag,
                            const std::vector<TrojanUserInfo>& users) {
    proxyman::inbound::UserSet set{ToPreparedUsers(users)};
    proxyman::inbound::UserStore::RemoveUsers(tag, set);
}

void Validator::ClearUsers(std::string_view tag) {
    proxyman::inbound::UserStore::ClearUsers(constants::protocol::kTrojan, tag);
}

bool Validator::Validate(std::string_view tag, std::string_view hash) const {
    return proxyman::inbound::UserStore::HasTrojanUser(tag, hash);
}

std::shared_ptr<const proxyman::inbound::UserStore::TrojanCredential>
Validator::FindUser(std::string_view tag, std::string_view hash) const {
    return proxyman::inbound::UserStore::FindTrojanUser(tag, hash);
}

size_t Validator::Size() const {
    return proxyman::inbound::UserStore::GetStats().trojan_users;
}

size_t Validator::SizeForTag(std::string_view tag) const {
    return proxyman::inbound::UserStore::SizeForProtocolTag(constants::protocol::kTrojan, tag);
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
