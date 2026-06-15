#include "acppnode/proxy/anytls/validator.hpp"

#include "acppnode/app/proxyman/inbound/prepared_config.hpp"
#include "acppnode/app/proxyman/inbound/user_store.hpp"
#include "acppnode/common/sharded_user_stats.hpp"
#include "acppnode/core/constants.hpp"

#include <openssl/evp.h>

namespace acpp::anytls {

namespace {

std::vector<proxyman::inbound::PreparedAnyTlsUser>
ToPreparedUsers(const std::vector<UserInfo>& users) {
    std::vector<proxyman::inbound::PreparedAnyTlsUser> prepared;
    prepared.reserve(users.size());
    for (const auto& user : users) {
        prepared.push_back(proxyman::inbound::PreparedAnyTlsUser{
            .password_hash = user.password_hash,
            .profile = user.profile,
        });
    }
    return prepared;
}

}  // namespace

std::array<uint8_t, 32> PasswordHash(std::string_view password) noexcept {
    std::array<uint8_t, 32> out{};
    unsigned int out_len = 0;
    EVP_Digest(password.data(), password.size(), out.data(), &out_len, EVP_sha256(), nullptr);
    return out;
}

struct Validator::Impl {
    UserOnlineTracker stats;
};

Validator::Validator()
    : impl_(std::make_unique<Impl>()) {}

Validator::~Validator() = default;
Validator::Validator(Validator&&) noexcept = default;
Validator& Validator::operator=(Validator&&) noexcept = default;

void Validator::ApplyUsers(std::string_view tag, const std::vector<UserInfo>& users) {
    proxyman::inbound::UserSet set;
    set.anytls_users = ToPreparedUsers(users);
    proxyman::inbound::UserStore::ApplyUsers(constants::protocol::kAnyTLS, tag, set);
}

void Validator::AddUsers(std::string_view tag, const std::vector<UserInfo>& users) {
    proxyman::inbound::UserSet set;
    set.anytls_users = ToPreparedUsers(users);
    proxyman::inbound::UserStore::AddUsers(constants::protocol::kAnyTLS, tag, set);
}

void Validator::RemoveUsers(std::string_view tag, const std::vector<UserInfo>& users) {
    proxyman::inbound::UserSet set;
    set.anytls_users = ToPreparedUsers(users);
    proxyman::inbound::UserStore::RemoveUsers(constants::protocol::kAnyTLS, tag, set);
}

void Validator::ClearUsers(std::string_view tag) {
    proxyman::inbound::UserStore::ClearUsers(constants::protocol::kAnyTLS, tag);
}

std::shared_ptr<const proxyman::inbound::UserStore::AnyTlsCredential> Validator::Validate(
    std::string_view tag,
    const std::array<uint8_t, 32>& password_hash) const {
    return proxyman::inbound::UserStore::FindAnyTlsUser(tag, password_hash);
}

size_t Validator::Size() const {
    return proxyman::inbound::UserStore::GetStats().anytls_users;
}

size_t Validator::SizeForTag(std::string_view tag) const {
    return proxyman::inbound::UserStore::SizeForProtocolTag(constants::protocol::kAnyTLS, tag);
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

}  // namespace acpp::anytls
