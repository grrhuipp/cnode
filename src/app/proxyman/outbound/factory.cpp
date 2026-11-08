#include "app/proxyman/outbound/factory.hpp"

#include "registration.hpp"

#include <map>
#include <stdexcept>

namespace proxyman::outbound {

namespace {

using CreatorMap = std::map<
    std::string,
    std::optional<PreparedOutboundProxy> (*)(
        const infra::OutboundSourceConfig& config),
    std::less<>>;

CreatorMap& Proxies() noexcept {
    static CreatorMap proxies;
    return proxies;
}

}  // namespace

void RegisterProxy(
    std::string_view protocol,
    std::optional<PreparedOutboundProxy> (*creator)(
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
    auto prepared = it->second(config);
    if (!prepared || !prepared->create) {
        return std::nullopt;
    }
    // Xray: the handler-level sendThrough wins over any protocol default.
    if (config.send_through) {
        prepared->sender.send_through = *config.send_through;
    }
    prepared->sender.passthrough = config.passthrough;
    return PreparedOutboundConfig{
        .tag = config.tag,
        .protocol = config.protocol,
        .sender = std::move(prepared->sender),
        .create = std::move(prepared->create),
    };
}

std::unique_ptr<::Outbound> NewProxy(
    const PreparedOutboundConfig& config,
    ::net::io_context& io_context,
    ::AwaitableTaskGroup& tasks) {
    if (!config.create) {
        throw std::logic_error(
            "prepared outbound '" + config.tag + "' has no creator");
    }
    auto proxy = config.create(config.tag, io_context, tasks);
    if (!proxy) {
        throw std::logic_error(
            "prepared outbound '" + config.tag + "' creator returned null");
    }
    return proxy;
}

bool HasProxy(std::string_view protocol) {
    return Proxies().contains(protocol);
}

}  // namespace proxyman::outbound
