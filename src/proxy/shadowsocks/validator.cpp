#include "validator.hpp"

#include "acppnode/app/proxyman/inbound/prepared_config.hpp"
#include "acppnode/common/sharded_user_stats.hpp"
#include "acppnode/core/constants.hpp"

#include <algorithm>

namespace acpp::ss {

namespace {

proxyman::inbound::PreparedAeadCipher ToPreparedCipher(SsCipherType type) {
    using Prepared = proxyman::inbound::PreparedAeadCipher;
    switch (type) {
        case SsCipherType::AES_128_GCM:
            return Prepared::AES_128_GCM;
        case SsCipherType::AES_256_GCM:
            return Prepared::AES_256_GCM;
        case SsCipherType::CHACHA20_POLY1305:
            return Prepared::CHACHA20_POLY1305;
        case SsCipherType::AES_128_GCM_2022:
            return Prepared::AES_128_GCM_2022;
        case SsCipherType::AES_256_GCM_2022:
            return Prepared::AES_256_GCM_2022;
        case SsCipherType::CHACHA20_POLY1305_2022:
            return Prepared::CHACHA20_POLY1305_2022;
    }
    return Prepared::AES_256_GCM;
}

SsCipherType ToSsCipher(proxyman::inbound::PreparedAeadCipher type) {
    using Prepared = proxyman::inbound::PreparedAeadCipher;
    switch (type) {
        case Prepared::AES_128_GCM:
            return SsCipherType::AES_128_GCM;
        case Prepared::AES_256_GCM:
            return SsCipherType::AES_256_GCM;
        case Prepared::CHACHA20_POLY1305:
            return SsCipherType::CHACHA20_POLY1305;
        case Prepared::AES_128_GCM_2022:
            return SsCipherType::AES_128_GCM_2022;
        case Prepared::AES_256_GCM_2022:
            return SsCipherType::AES_256_GCM_2022;
        case Prepared::CHACHA20_POLY1305_2022:
            return SsCipherType::CHACHA20_POLY1305_2022;
    }
    return SsCipherType::AES_256_GCM;
}

proxyman::inbound::PreparedKeyBytes ToPreparedKey(KeyBytes key) {
    proxyman::inbound::PreparedKeyBytes prepared;
    prepared.assign(key.span());
    return prepared;
}

KeyBytes ToSsKey(const proxyman::inbound::PreparedKeyBytes& key) {
    KeyBytes out;
    out.assign(key.span());
    return out;
}

std::vector<proxyman::inbound::PreparedShadowsocksUser>
ToPreparedUsers(const std::vector<SsUserInfo>& users) {
    std::vector<proxyman::inbound::PreparedShadowsocksUser> prepared;
    prepared.reserve(users.size());
    for (const auto& user : users) {
        prepared.push_back(proxyman::inbound::PreparedShadowsocksUser{
            .password = user.password,
            .derived_key = ToPreparedKey(user.derived_key),
            .identity_key = ToPreparedKey(user.identity_key),
            .cipher_type = ToPreparedCipher(user.cipher_type),
            .key_size = user.key_size,
            .salt_size = user.salt_size,
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

void Validator::ApplyUsers(std::string_view tag,
                           const std::vector<SsUserInfo>& users) {
    proxyman::inbound::UserSet set{ToPreparedUsers(users)};
    proxyman::inbound::UserStore::ApplyUsers(tag, set);
}

void Validator::AddUsers(std::string_view tag,
                         const std::vector<SsUserInfo>& users) {
    proxyman::inbound::UserSet set{ToPreparedUsers(users)};
    proxyman::inbound::UserStore::AddUsers(tag, set);
}

void Validator::RemoveUsers(std::string_view tag,
                            const std::vector<SsUserInfo>& users) {
    proxyman::inbound::UserSet set{ToPreparedUsers(users)};
    proxyman::inbound::UserStore::RemoveUsers(tag, set);
}

void Validator::ClearUsers(std::string_view tag) {
    proxyman::inbound::UserStore::ClearUsers(constants::protocol::kShadowsocks, tag);
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
        user.derived_key = ToSsKey(credential.derived_key);
        user.identity_key = ToSsKey(credential.identity_key);
        user.cipher_type = ToSsCipher(credential.cipher_type);
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
    user.derived_key = ToSsKey(credential->derived_key);
    user.identity_key = ToSsKey(credential->identity_key);
    user.cipher_type = ToSsCipher(credential->cipher_type);
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

size_t Validator::SizeForTag(std::string_view tag) const {
    return proxyman::inbound::UserStore::SizeForProtocolTag(
        constants::protocol::kShadowsocks, tag);
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
