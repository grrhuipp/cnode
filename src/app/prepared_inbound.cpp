#include "app/prepared_inbound.hpp"

#include "app/proxyman/inbound/factory.hpp"
#include "infra/config_types.hpp"
#include "transport/internet/transport_security.hpp"

#include <stdexcept>
#include <utility>
#include <variant>


std::shared_ptr<const proxyman::inbound::UserSet> PrepareInboundUsers(
    const proxyman::inbound::BuildRequest& request,
    std::span<const InboundUserSpec> users) {
    auto prepared = proxyman::inbound::BuildUsers(request, users);
    if (!prepared) {
        throw std::invalid_argument(
            "inbound '" + request.tag + "' has invalid users");
    }
    const size_t count = std::visit(
        [](const auto& values) { return values.size(); }, *prepared);
    if (count != users.size()) {
        throw std::invalid_argument(
            "inbound '" + request.tag + "' has an incomplete user snapshot");
    }
    return std::make_shared<const proxyman::inbound::UserSet>(std::move(*prepared));
}

PreparedInbound PrepareInbound(const InboundSpec& spec) {
    if (!proxyman::inbound::HasProxy(spec.protocol)) {
        throw std::invalid_argument(
            "inbound '" + spec.tag + "' has unsupported protocol '" +
            spec.protocol + "'");
    }
    auto build_request = proxyman::inbound::PrepareBuildRequest(
        spec.protocol, spec.tag, spec.settings);
    if (!build_request) {
        throw std::invalid_argument(
            "inbound '" + spec.tag + "' has invalid protocol settings");
    }
    auto users = PrepareInboundUsers(*build_request, spec.users);

    StreamSettings stream_settings = spec.stream_settings;
    TransportSecurity::Prepare(stream_settings, StreamEndpointRole::Inbound);

    return PreparedInbound{
        .binding = PortBinding{
            .port = spec.port,
            .protocol = spec.protocol,
            .tag = spec.tag,
            .listen = spec.listen,
        },
        .receiver = proxyman::inbound::MakeReceiverSettings(
            spec.tag,
            spec.all_tags,
            spec.protocol,
            std::move(stream_settings),
            spec.sniffing,
            spec.proxy_protocol,
            spec.outbound_policy,
            spec.accounting_key),
        .build_request = std::move(*build_request),
        .users = std::move(users),
    };
}

