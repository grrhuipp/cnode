#include "acppnode/app/proxyman/inbound/factory.hpp"

#include "acppnode/app/proxyman/inbound/udp_handler.hpp"
#include "acppnode/proxy/inbound.hpp"

#include <map>
#include <ranges>
#include <stdexcept>

namespace acpp::proxyman::inbound {

namespace {

using RegistrationMap = std::map<std::string, ProxyRegistration, std::less<>>;

RegistrationMap& Registrations() noexcept {
    static RegistrationMap registrations;
    return registrations;
}

}  // namespace

void RegisterProxy(
    std::string_view protocol,
    ProxyRegistration registration) {
    const bool has_user_builders = registration.build_static_users ||
                                   registration.build_users;
    if (protocol.empty() || !registration.create_runtime ||
        !registration.create_tcp_handler ||
        has_user_builders != registration.user_protocol.has_value()) {
        throw std::invalid_argument(
            "invalid inbound protocol registration for '" +
            std::string(protocol) + "'");
    }
    if (!Registrations().try_emplace(
            std::string(protocol), std::move(registration)).second) {
        throw std::logic_error(
            "duplicate inbound protocol registration for '" +
            std::string(protocol) + "'");
    }
}

bool HasProxy(std::string_view protocol) {
    return Registrations().contains(protocol);
}

std::vector<std::string> RegisteredProtocols() {
    auto& registrations = Registrations();
    std::vector<std::string> result;
    result.reserve(registrations.size());
    for (const auto& name : registrations | std::views::keys) {
        result.push_back(name);
    }
    return result;
}

std::optional<UserProtocol> RegisteredUserProtocol(
    std::string_view protocol) {
    auto& registrations = Registrations();
    auto it = registrations.find(protocol);
    return it == registrations.end() ? std::nullopt : it->second.user_protocol;
}

std::unique_ptr<ProtocolRuntime> NewProtocolRuntime(
    std::string_view protocol) {
    auto& registrations = Registrations();
    auto it = registrations.find(protocol);
    if (it == registrations.end() || !it->second.create_runtime) {
        return nullptr;
    }
    return it->second.create_runtime();
}

std::unique_ptr<::acpp::Inbound> NewHandler(
    std::string_view protocol,
    const ProtocolDeps& deps,
    ::acpp::ConnectionLimiterPtr limiter,
    const BuildRequest& req) {
    auto& registrations = Registrations();
    auto it = registrations.find(protocol);
    if (it == registrations.end() || !it->second.create_tcp_handler) {
        return nullptr;
    }
    return it->second.create_tcp_handler(deps, limiter, req);
}

UdpHandlerBuildResult NewUdpHandler(
    std::string_view protocol,
    const ProtocolDeps& deps,
    ::acpp::ConnectionLimiterPtr limiter,
    const BuildRequest& req) {
    auto& registrations = Registrations();
    auto it = registrations.find(protocol);
    if (it == registrations.end()) {
        return {UdpHandlerBuildStatus::Failed, nullptr};
    }
    if (!it->second.create_udp_handler) {
        return {UdpHandlerBuildStatus::Unsupported, nullptr};
    }
    auto handler = it->second.create_udp_handler(deps, limiter, req);
    if (!handler) {
        return {UdpHandlerBuildStatus::Failed, nullptr};
    }
    return {UdpHandlerBuildStatus::Ready, std::move(handler)};
}

std::optional<UserSet> BuildStaticUsers(
    std::string_view protocol,
    std::string_view tag,
    const ::acpp::StaticUserConfig& config) {
    auto& registrations = Registrations();
    auto it = registrations.find(protocol);
    if (it == registrations.end() || !it->second.build_static_users) {
        return std::nullopt;
    }
    auto result = it->second.build_static_users(tag, config);
    if (result && UserProtocolOf(*result) != *it->second.user_protocol) {
        return std::nullopt;
    }
    return result;
}

std::optional<UserSet> BuildUsers(
    std::string_view protocol,
    const BuildRequest& req,
    std::span<const RuntimeUser> users) {
    auto& registrations = Registrations();
    auto it = registrations.find(protocol);
    if (it == registrations.end() || !it->second.build_users) {
        return std::nullopt;
    }
    auto result = it->second.build_users(req, users);
    if (result && UserProtocolOf(*result) != *it->second.user_protocol) {
        return std::nullopt;
    }
    return result;
}

}  // namespace acpp::proxyman::inbound
