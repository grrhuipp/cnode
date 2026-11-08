#include "app/proxyman/inbound/factory.hpp"

#include "infra/config_types.hpp"
#include "proxy/inbound.hpp"

#include <map>
#include <stdexcept>

namespace proxyman::inbound {

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
    const bool has_user_builders = registration.build_users != nullptr;
    const bool has_tcp = registration.create_tcp_handler != nullptr;
    const bool has_packet_datagrams =
        registration.create_datagram_handler != nullptr;
    const bool transport_consistent =
        (registration.datagram_transport == DatagramTransport::Packet) ==
            has_packet_datagrams;
    if (protocol.empty() || !registration.create_runtime ||
        !has_tcp ||
        !transport_consistent ||
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


std::optional<UserProtocol> RegisteredUserProtocol(
    std::string_view protocol) {
    auto& registrations = Registrations();
    auto it = registrations.find(protocol);
    return it == registrations.end() ? std::nullopt : it->second.user_protocol;
}

DatagramTransport RegisteredDatagramTransport(
    std::string_view protocol) {
    auto& registrations = Registrations();
    auto it = registrations.find(protocol);
    return it == registrations.end()
        ? DatagramTransport::None
        : it->second.datagram_transport;
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

std::unique_ptr<::Inbound> NewHandler(
    std::string_view protocol,
    ProtocolRuntime& runtime,
    ::StatsShard& stats,
    ::ConnectionLimiter* limiter,
    const BuildRequest& req) {
    auto& registrations = Registrations();
    auto it = registrations.find(protocol);
    if (it == registrations.end() || !it->second.create_tcp_handler) {
        return nullptr;
    }
    return it->second.create_tcp_handler(runtime, stats, limiter, req);
}

DatagramHandlerBuildResult NewDatagramHandler(
    std::string_view protocol,
    ProtocolRuntime& runtime,
    ::StatsShard& stats,
    ::ConnectionLimiter* limiter,
    const BuildRequest& req) {
    auto& registrations = Registrations();
    auto it = registrations.find(protocol);
    if (it == registrations.end()) {
        return {DatagramHandlerBuildStatus::Failed, nullptr};
    }
    if (!it->second.create_datagram_handler) {
        return {DatagramHandlerBuildStatus::Unsupported, nullptr};
    }
    auto handler =
        it->second.create_datagram_handler(runtime, stats, limiter, req);
    if (!handler) {
        return {DatagramHandlerBuildStatus::Failed, nullptr};
    }
    return {DatagramHandlerBuildStatus::Ready, std::move(handler)};
}

std::optional<BuildRequest> PrepareBuildRequest(
    std::string_view protocol,
    std::string_view tag,
    const ::InboundProtocolSettings& settings) {
    auto& registrations = Registrations();
    auto it = registrations.find(protocol);
    if (it == registrations.end()) {
        return std::nullopt;
    }

    BuildRequest request{
        .tag = std::string(tag),
        .protocol = std::string(protocol),
        .settings = {},
    };
    if (it->second.prepare_settings) {
        auto prepared = it->second.prepare_settings(tag, settings);
        if (!prepared) {
            return std::nullopt;
        }
        request.settings = std::move(*prepared);
    }
    return request;
}

std::optional<UserSet> BuildUsers(
    const BuildRequest& req,
    std::span<const ::InboundUserSpec> users) {
    auto& registrations = Registrations();
    auto it = registrations.find(req.protocol);
    if (it == registrations.end() || !it->second.build_users) {
        return std::nullopt;
    }
    auto result = it->second.build_users(req, users);
    if (result && UserProtocolOf(*result) != *it->second.user_protocol) {
        return std::nullopt;
    }
    return result;
}

}  // namespace proxyman::inbound
