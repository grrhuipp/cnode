#include "acppnode/app/proxyman/outbound/factory.hpp"

#include "source_config.hpp"

#include <map>
#include <ranges>

namespace acpp::proxyman::outbound {

namespace {

using CreatorMap = std::map<
    std::string,
    std::optional<PreparedOutboundConfig> (*)(
        const OutboundSourceConfig& config),
    std::less<>>;

CreatorMap& Proxies() noexcept {
    static CreatorMap proxies;
    return proxies;
}

}  // namespace

bool RegisterProxy(
    std::string_view protocol,
    std::optional<PreparedOutboundConfig> (*creator)(
        const OutboundSourceConfig& config)) {
    Proxies().insert_or_assign(std::string(protocol), std::move(creator));
    return true;
}

std::optional<PreparedOutboundConfig> PrepareOutboundConfig(
    const OutboundSourceConfig& config) {
    auto& proxies = Proxies();
    auto it = proxies.find(config.protocol);
    if (it == proxies.end()) {
        return std::nullopt;
    }
    return it->second(config);
}

std::vector<PreparedOutboundConfig> PrepareOutboundConfigs(
    const std::vector<OutboundSourceConfig>& configs) {
    std::vector<PreparedOutboundConfig> prepared;
    prepared.reserve(configs.size());
    for (const auto& config : configs) {
        auto entry = PrepareOutboundConfig(config);
        if (entry) {
            prepared.push_back(std::move(*entry));
        }
    }
    return prepared;
}

std::unique_ptr<Handler> NewHandler(
    const PreparedOutboundConfig& config,
    ::acpp::net::io_context& io_context,
    ::acpp::app::dns::DNS& dns,
    ::acpp::UDPSessionManager* udp_mgr,
    ::acpp::StatsShard& stats,
    std::chrono::seconds dial_timeout) {

    if (!config.create) {
        return nullptr;
    }
    auto proxy = config.create(io_context, dns, udp_mgr, dial_timeout);
    if (!proxy) {
        return nullptr;
    }
    return std::make_unique<Handler>(std::string(proxy->Tag()), std::move(proxy), stats);
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
