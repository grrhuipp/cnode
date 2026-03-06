#include "acppnode/protocol/inbound_registry.hpp"
#include "acppnode/protocol/shadowsocks/ss_udp_inbound.hpp"

#include <ranges>

namespace acpp {

InboundFactory& InboundFactory::Instance() noexcept {
    static InboundFactory instance;
    return instance;
}

void InboundFactory::Register(
    std::string_view protocol,
    InboundProtocolRegistration registration) {
    regs_.insert_or_assign(std::string(protocol), std::move(registration));
}

bool InboundFactory::Has(std::string_view protocol) const {
    return regs_.contains(protocol);
}

std::vector<std::string> InboundFactory::RegisteredProtocols() const {
    std::vector<std::string> result;
    result.reserve(regs_.size());
    for (const auto& name : regs_ | std::views::keys) {
        result.push_back(name);
    }
    return result;
}

std::shared_ptr<IInboundHandler> InboundFactory::CreateTcpHandler(
    std::string_view protocol,
    const InboundProtocolDeps& deps,
    ConnectionLimiterPtr limiter,
    const InboundBuildRequest& req) const {
    auto it = regs_.find(protocol);
    if (it == regs_.end() || !it->second.create_tcp_handler) {
        return nullptr;
    }
    auto handler = it->second.create_tcp_handler(deps, std::move(limiter), req);
    if (!handler) {
        return nullptr;
    }
    return std::shared_ptr<IInboundHandler>(std::move(handler));
}

std::unique_ptr<ss::SsUdpInboundHandler> InboundFactory::CreateUdpHandler(
    std::string_view protocol,
    const InboundProtocolDeps& deps,
    ConnectionLimiterPtr limiter,
    const InboundBuildRequest& req) const {
    auto it = regs_.find(protocol);
    if (it == regs_.end() || !it->second.create_udp_handler) {
        return nullptr;
    }
    return it->second.create_udp_handler(deps, std::move(limiter), req);
}

bool InboundFactory::LoadStaticUsers(
    std::string_view protocol,
    std::string_view tag,
    const boost::json::object& settings) const {
    auto it = regs_.find(protocol);
    if (it == regs_.end() || !it->second.load_static_users) {
        return false;
    }
    return it->second.load_static_users(tag, settings);
}

void InboundFactory::SyncWorkerUsers(
    std::string_view protocol,
    const InboundProtocolDeps& deps,
    std::string_view tag) const {
    auto it = regs_.find(protocol);
    if (it == regs_.end() || !it->second.sync_worker_users) {
        return;
    }
    it->second.sync_worker_users(deps, tag);
}

void InboundFactory::UpdatePanelUsers(
    std::string_view protocol,
    std::string_view tag,
    const NodeConfig& node_config,
    const std::vector<PanelUser>& panel_users) const {
    auto it = regs_.find(protocol);
    if (it == regs_.end() || !it->second.update_panel_users) {
        return;
    }
    it->second.update_panel_users(tag, node_config, panel_users);
}

void InboundFactory::ClearUsers(std::string_view protocol, std::string_view tag) const {
    auto it = regs_.find(protocol);
    if (it == regs_.end() || !it->second.clear_users) {
        return;
    }
    it->second.clear_users(tag);
}

}  // namespace acpp
