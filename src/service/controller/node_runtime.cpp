#include "node_runtime.hpp"
#include "inboundbuilder.hpp"
#include "outboundbuilder.hpp"

#include "acppnode/app/proxyman/inbound/user_store.hpp"
#include "acppnode/app/proxyman/inbound/receiver_settings.hpp"
#include "acppnode/app/proxyman/inbound/factory.hpp"
#include "acppnode/runtime/runtime.hpp"
#include "acppnode/infra/log.hpp"

#include <cstdint>
#include <exception>
#include <vector>

namespace acpp::controller {

net::awaitable<void> NodeRuntime::RemoveInbound(const std::string& tag) {
    co_await runtime_.UnregisterListener(tag);
}

net::awaitable<void> NodeRuntime::RemoveOutbound(const std::string& tag) {
    co_await runtime_.RemoveOutbound(tag);
}

net::awaitable<bool> NodeRuntime::AddOutbound(const std::string& tag) {
    auto prepared = controller::OutboundBuilder(tag, config_);
    if (!prepared) co_return false;
    co_await runtime_.AddOutbound(std::move(*prepared));
    co_return true;
}

net::awaitable<bool> NodeRuntime::AddInbound(const api::NodeInfo& node_config) {
    const int node_id = config_.NodeIDs.Front();
    const auto& panel_name = config_.Name;
    auto inbound = controller::InboundBuilder(config_, node_config);
    if (!proxyman::inbound::HasProxy(inbound.protocol)) {
        LOG_WARN("Node {}/{}: unsupported inbound protocol '{}'", panel_name, node_id, inbound.protocol);
        co_return false;
    }

    bool ready = false;
    std::exception_ptr failure;
    try {
        auto receiver = proxyman::inbound::MakeReceiverSettings(inbound.tag,
            std::vector<std::string>{inbound.tag, std::string(constants::protocol::kNode)},
            inbound.protocol, inbound.stream_settings, inbound.sniff, &limiter_,
            inbound.proxy_protocol, routing::RouteWithFallback(inbound.tag));
        const bool registered = co_await runtime_.RegisterInbound(
            &limiter_, inbound.handler_request, std::move(receiver));
        if (registered) {
            const bool tcp = co_await runtime_.AddListener(inbound.binding);
            const bool udp = tcp && (co_await runtime_.AddUdpListener(
                inbound.binding, &limiter_, inbound.handler_request));
            ready = tcp && udp;
        }
    } catch (...) { failure = std::current_exception(); }

    if (!ready) {
        const bool previous = co_await net::this_coro::throw_if_cancelled();
        co_await net::this_coro::throw_if_cancelled(false);
        co_await RemoveInbound(inbound.tag);
        co_await net::this_coro::throw_if_cancelled(previous);
        if (failure) std::rethrow_exception(failure);
        LOG_WARN("Node {}/{}: inbound bind or preparation failed, tag={}", panel_name, node_id, inbound.tag);
        co_return false;
    }
    LOG_CONSOLE("inbound ready tag={} port={} protocol={}", inbound.tag, node_config.Port, inbound.protocol);
    co_return true;
}

net::awaitable<void> NodeRuntime::UpdateRules(const std::string& tag,
    const std::vector<api::DetectRule>& rules) {
    co_await runtime_.UpdateRule(tag, rules);
}

void NodeRuntime::ClearUsers(const std::string& tag, const std::string& protocol) {
    const auto user_protocol =
        proxyman::inbound::RegisteredUserProtocol(protocol);
    if (!user_protocol) {
        return;
    }

    proxyman::inbound::UserStore::ClearUsers(*user_protocol, tag);
}

void NodeRuntime::ApplyUsers(const std::string& tag, const proxyman::inbound::UserSet& users) {
    proxyman::inbound::UserStore::ApplyUsers(tag, users);
}

}  // namespace acpp::controller
