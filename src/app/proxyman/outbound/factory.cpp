#include "acppnode/app/proxyman/outbound/factory.hpp"

#include "source_config.hpp"

#include <map>
#include <ranges>
#include <stdexcept>

namespace acpp::proxyman::outbound {

namespace {

using CreatorMap = std::map<
    std::string,
    std::optional<PreparedOutboundCreator> (*)(
        const OutboundSourceConfig& config),
    std::less<>>;

CreatorMap& Proxies() noexcept {
    static CreatorMap proxies;
    return proxies;
}

}  // namespace

void RegisterProxy(
    std::string_view protocol,
    std::optional<PreparedOutboundCreator> (*creator)(
        const OutboundSourceConfig& config)) {
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
    const OutboundSourceConfig& config) {
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
        return nullptr;
    }
    auto proxy = config.create(
        config.tag, io_context, dns, udp_mgr, dial_timeout);
    if (!proxy || proxy->Tag() != config.tag) {
        return nullptr;
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
