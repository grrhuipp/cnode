#include "acppnode/app/proxyman/inbound/factory.hpp"

#include "acppnode/app/proxyman/inbound/udp_handler.hpp"
#include "acppnode/proxy/inbound.hpp"

#include <map>
#include <ranges>

namespace acpp::proxyman::inbound {

namespace {

using RegistrationMap = std::map<std::string, ProxyRegistration, std::less<>>;

RegistrationMap& Registrations() noexcept {
    static RegistrationMap registrations;
    return registrations;
}

}  // namespace

bool RegisterProxy(
    std::string_view protocol,
    ProxyRegistration registration) {
    Registrations().insert_or_assign(std::string(protocol), std::move(registration));
    return true;
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

std::unique_ptr<UdpHandler> NewUdpHandler(
    std::string_view protocol,
    const ProtocolDeps& deps,
    ::acpp::ConnectionLimiterPtr limiter,
    const BuildRequest& req) {
    auto& registrations = Registrations();
    auto it = registrations.find(protocol);
    if (it == registrations.end() || !it->second.create_udp_handler) {
        return nullptr;
    }
    return it->second.create_udp_handler(deps, limiter, req);
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
    return it->second.build_static_users(tag, config);
}

void ApplyWorkerUsers(
    std::string_view protocol,
    const ProtocolDeps& deps,
    std::string_view tag,
    const UserSet& users) {
    auto& registrations = Registrations();
    auto it = registrations.find(protocol);
    if (it == registrations.end() || !it->second.apply_worker_users) {
        return;
    }
    it->second.apply_worker_users(deps, tag, users);
}

void AddWorkerUsers(
    std::string_view protocol,
    const ProtocolDeps& deps,
    std::string_view tag,
    const UserSet& users) {
    auto& registrations = Registrations();
    auto it = registrations.find(protocol);
    if (it == registrations.end() || !it->second.add_worker_users) {
        return;
    }
    it->second.add_worker_users(deps, tag, users);
}

void RemoveWorkerUsers(
    std::string_view protocol,
    const ProtocolDeps& deps,
    std::string_view tag,
    const UserSet& users) {
    auto& registrations = Registrations();
    auto it = registrations.find(protocol);
    if (it == registrations.end() || !it->second.remove_worker_users) {
        return;
    }
    it->second.remove_worker_users(deps, tag, users);
}

void ClearWorkerUsers(
    std::string_view protocol,
    const ProtocolDeps& deps,
    std::string_view tag) {
    auto& registrations = Registrations();
    auto it = registrations.find(protocol);
    if (it == registrations.end() || !it->second.clear_worker_users) {
        return;
    }
    it->second.clear_worker_users(deps, tag);
}

}  // namespace acpp::proxyman::inbound
