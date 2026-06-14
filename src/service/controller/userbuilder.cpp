#include "controller_impl.hpp"

#include "acppnode/core/constants.hpp"
#include "acppnode/app/proxyman/inbound/prepared_config.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/proxy/anytls/user_info.hpp"
#include "acppnode/proxy/shadowsocks/validator.hpp"
#include "acppnode/proxy/trojan/validator.hpp"
#include "acppnode/proxy/vmess/account.hpp"

#include <format>

namespace acpp {

std::string Controller::Impl::BuildUserTag(std::string_view tag,
                                     const api::UserInfo& user) const {
    return std::format("{}|{}|{}", tag, user.Email, user.UID);
}

uint32_t Controller::Impl::DeviceLimitOf(const api::UserInfo& user) const noexcept {
    return user.DeviceLimit > 0 ? static_cast<uint32_t>(user.DeviceLimit) : 0;
}

std::optional<proxyman::inbound::UserSet> Controller::Impl::BuildVmessUsers(
    std::string_view tag,
    const std::vector<api::UserInfo>& api_users) const {
    std::vector<vmess::MemoryAccount> users;
    users.reserve(api_users.size());

    for (const auto& user_info : api_users) {
        if (auto user = vmess::MemoryAccount::FromUUID(
                user_info.UUID,
                user_info.UID,
                BuildUserTag(tag, user_info),
                user_info.SpeedLimit,
                DeviceLimitOf(user_info))) {
            users.push_back(*user);
        }
    }

    proxyman::inbound::UserSet result;
    result.vmess_accounts = std::move(users);
    return result;
}

std::optional<proxyman::inbound::UserSet> Controller::Impl::BuildTrojanUsers(
    std::string_view tag,
    const std::vector<api::UserInfo>& api_users) const {
    std::vector<trojan::TrojanUserInfo> users;
    users.reserve(api_users.size());

    for (const auto& user_info : api_users) {
        const std::string& password =
            user_info.Passwd.empty() ? user_info.UUID : user_info.Passwd;

        trojan::TrojanUserInfo info;
        info.password_hash = trojan::HashPassword(password);
        info.email         = BuildUserTag(tag, user_info);
        info.user_id       = user_info.UID;
        info.speed_limit   = user_info.SpeedLimit;
        info.device_limit  = DeviceLimitOf(user_info);
        users.push_back(std::move(info));
    }

    proxyman::inbound::UserSet result;
    result.trojan_users = std::move(users);
    return result;
}

std::optional<proxyman::inbound::UserSet> Controller::Impl::BuildShadowsocksUsers(
    std::string_view tag,
    const api::NodeInfo& node_config,
    const std::vector<api::UserInfo>& api_users) const {
    const std::string method = node_config.CypherMethod.empty()
        ? std::string(constants::protocol::kAes256Gcm)
        : node_config.CypherMethod;

    auto cipher_info = ss::ParseCipherMethod(method);
    if (!cipher_info) {
        LOG_WARN("UpdateUsers: unknown SS cipher '{}', skip update", method);
        return std::nullopt;
    }

    std::vector<ss::SsUserInfo> users;
    users.reserve(api_users.size());

    for (const auto& user_info : api_users) {
        const std::string& password =
            user_info.Passwd.empty() ? user_info.UUID : user_info.Passwd;

        ss::SsUserInfo info;
        info.password     = password;
        info.email        = BuildUserTag(tag, user_info);
        info.user_id      = user_info.UID;
        info.speed_limit  = user_info.SpeedLimit;
        info.device_limit = DeviceLimitOf(user_info);
        info.cipher_type  = cipher_info->type;
        info.key_size     = cipher_info->key_size;
        info.salt_size    = cipher_info->salt_size;
        info.derived_key  = ss::DeriveKey(password, cipher_info->key_size);
        users.push_back(std::move(info));
    }

    proxyman::inbound::UserSet result;
    result.ss_users = std::move(users);
    return result;
}

std::optional<proxyman::inbound::UserSet> Controller::Impl::BuildUsersForInbound(
    std::string_view protocol,
    std::string_view tag,
    const api::NodeInfo& node_config,
    const std::vector<api::UserInfo>& api_users) const {
    if (protocol == constants::protocol::kVmess) {
        return BuildVmessUsers(tag, api_users);
    }
    if (protocol == constants::protocol::kTrojan) {
        return BuildTrojanUsers(tag, api_users);
    }
    if (protocol == constants::protocol::kShadowsocks) {
        return BuildShadowsocksUsers(tag, node_config, api_users);
    }
    if (protocol == constants::protocol::kAnyTLS) {
        std::vector<anytls::UserInfo> users;
        users.reserve(api_users.size());
        for (const auto& user_info : api_users) {
            const std::string& password =
                user_info.Passwd.empty() ? user_info.UUID : user_info.Passwd;
            anytls::UserInfo info;
            info.password_hash = anytls::PasswordHash(password);
            info.email = BuildUserTag(tag, user_info);
            info.user_id = user_info.UID;
            info.speed_limit = user_info.SpeedLimit;
            info.device_limit = DeviceLimitOf(user_info);
            users.push_back(std::move(info));
        }
        proxyman::inbound::UserSet result;
        result.anytls_users = std::move(users);
        return result;
    }
    return std::nullopt;
}

}  // namespace acpp
