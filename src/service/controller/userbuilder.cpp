#include "controller_impl.hpp"

#include "acppnode/app/proxyman/inbound/factory.hpp"
#include "acppnode/core/constants.hpp"
#include "acppnode/infra/config_types.hpp"
#include "acppnode/infra/log.hpp"

#include <format>
#include <utility>

namespace acpp {

std::string Controller::Impl::BuildUserTag(std::string_view tag,
                                           const api::UserInfo& user) const {
    return std::format("{}|{}|{}", tag, user.Email, user.UID);
}

std::optional<proxyman::inbound::UserSet> Controller::Impl::BuildUsersForInbound(
    std::string_view protocol,
    std::string_view tag,
    const api::NodeInfo& node_config,
    const std::vector<api::UserInfo>& api_users) const {
    StaticUserConfig protocol_source;
    protocol_source.method = node_config.CypherMethod.empty()
        ? std::string(constants::protocol::kAes256Gcm)
        : node_config.CypherMethod;
    protocol_source.identity_password = node_config.ShadowsocksServerKey;
    auto req = proxyman::inbound::PrepareBuildRequest(
        protocol,
        tag,
        protocol_source);
    if (!req) {
        LOG_WARN(
            "BuildUsersForInbound: invalid protocol settings for '{}'",
            protocol);
        return std::nullopt;
    }

    std::vector<proxyman::inbound::RuntimeUser> users;
    users.reserve(api_users.size());
    for (const auto& api_user : api_users) {
        proxyman::inbound::RuntimeUser user;
        user.user_id = api_user.UID;
        user.email = BuildUserTag(tag, api_user);
        user.password = api_user.Passwd.empty() ? api_user.UUID : api_user.Passwd;
        user.uuid = api_user.UUID;
        user.flow = api_user.Flow;
        user.speed_limit = api_user.SpeedLimit;
        user.device_limit = api_user.DeviceLimit;
        users.push_back(std::move(user));
    }

    auto result = proxyman::inbound::BuildUsers(protocol, *req, users);
    if (!result) {
        LOG_WARN("BuildUsersForInbound: unsupported user builder for protocol '{}'", protocol);
    }
    return result;
}

}  // namespace acpp
