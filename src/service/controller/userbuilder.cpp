#include "controller_impl.hpp"

#include "acppnode/app/proxyman/inbound/factory.hpp"
#include "acppnode/infra/log.hpp"

#include <format>
#include <utility>
#include <variant>

namespace acpp {

std::string Controller::Impl::BuildUserTag(std::string_view tag,
                                           const api::UserInfo& user) const {
    return std::format("{}|{}|{}", tag, user.Email, user.UID);
}

std::optional<proxyman::inbound::UserSet> Controller::Impl::BuildUsersForInbound(
    const controller::InboundBuild& inbound,
    const api::NodeInfo& node_config,
    const std::vector<api::UserInfo>& api_users) const {

    std::vector<proxyman::inbound::RuntimeUser> users;
    users.reserve(api_users.size());
    for (const auto& api_user : api_users) {
        proxyman::inbound::RuntimeUser user;
        user.user_id = api_user.UID;
        user.email = BuildUserTag(inbound.tag, api_user);
        user.credential = api_user.UUID;
        user.flow = api_user.Flow.empty() ? node_config.Flow : api_user.Flow;
        user.speed_limit = api_user.SpeedLimit;
        user.device_limit = api_user.DeviceLimit;
        users.push_back(std::move(user));
    }

    auto result = proxyman::inbound::BuildUsers(
        inbound.protocol, inbound.handler_request, users);
    if (!result) {
        LOG_WARN("BuildUsersForInbound: unsupported user builder for protocol '{}'", inbound.protocol);
    } else if (std::visit([](const auto& prepared) { return prepared.size(); }, *result) != api_users.size()) {
        // Invalid credentials must not turn a non-empty panel response into a
        // partial or empty authentication snapshot.
        LOG_WARN("BuildUsersForInbound: incomplete user snapshot for protocol '{}'", inbound.protocol);
        return std::nullopt;
    }
    return result;
}

}  // namespace acpp
