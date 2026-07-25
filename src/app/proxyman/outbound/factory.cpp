#include "acppnode/app/proxyman/outbound/factory.hpp"

#include "registration.hpp"

#include <map>
#include <ranges>
#include <stdexcept>

namespace acpp::proxyman::outbound {

namespace {

using CreatorMap = std::map<
    std::string,
    std::optional<PreparedOutboundCreator> (*)(
        const infra::OutboundSourceConfig& config),
    std::less<>>;

CreatorMap& Proxies() noexcept {
    static CreatorMap proxies;
    return proxies;
}

}  // namespace

void RegisterProxy(
    std::string_view protocol,
    std::optional<PreparedOutboundCreator> (*creator)(
        const infra::OutboundSourceConfig& config)) {
    if (protocol.empty() || !creator) {
        throw std::invalid_argument(
            "invalid outbound protocol registration for '" +
            std::string(protocol) + "'");
    }
    if (!Proxies().try_emplace(std::string(protocol), creator).second) {
        throw std::logic_error(
            "duplicate outbound protocol registration for '" +
            std::string(protocol) + "'");
    }
}

std::optional<PreparedOutboundConfig> PrepareOutboundConfig(
    const infra::OutboundSourceConfig& config) {
    auto& proxies = Proxies();
    auto it = proxies.find(config.protocol);
    if (it == proxies.end()) {
        return std::nullopt;
    }
    auto creator = it->second(config);
    if (!creator || !*creator) {
        return std::nullopt;
    }
    return PreparedOutboundConfig{
        .tag = config.tag,
        .protocol = config.protocol,
        .create = std::move(*creator),
    };
}

std::unique_ptr<::acpp::Outbound> NewHandler(
    const PreparedOutboundConfig& config,
    ::acpp::net::io_context& io_context,
    ::acpp::app::dns::DNS& dns,
    ::acpp::UDPSessionManager* udp_mgr,
    std::chrono::seconds dial_timeout) {

    if (!config.create) {
        throw std::logic_error(
            "prepared outbound '" + config.tag + "' has no creator");
    }
    auto proxy = config.create(
        config.tag, io_context, dns, udp_mgr, dial_timeout);
    if (!proxy) {
        throw std::logic_error(
            "prepared outbound '" + config.tag + "' creator returned null");
    }
    if (proxy->Tag() != config.tag) {
        throw std::logic_error(
            "prepared outbound '" + config.tag +
            "' created handler with tag '" + std::string(proxy->Tag()) + "'");
    }
    return proxy;
}

bool HasProxy(std::string_view protocol) {
    return Proxies().contains(protocol);
}

std::vector<std::string> RegisteredProtocols() {
    auto& proxies = Proxies();
    std::vector<std::string> result;
    result.reserve(proxies.size());
    for (const auto& name : proxies | std::views::keys) {
        result.push_back(name);
    }
    return result;
}

}  // namespace acpp::proxyman::outbound
