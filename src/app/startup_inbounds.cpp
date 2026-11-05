#include "startup_inbounds.hpp"
#include "../infra/config_semantics.hpp"

#include "acppnode/app/proxyman/inbound/factory.hpp"
#include "acppnode/core/constants.hpp"
#include "acppnode/core/naming.hpp"
#include "acppnode/infra/config_types.hpp"
#include "acppnode/transport/internet/transport_security.hpp"

#include <stdexcept>
#include <utility>

namespace acpp {

namespace {

StaticInboundConfig MakeTestInboundConfig() {
    StaticInboundConfig source;
    source.protocol = constants::protocol::kDefaultNodeProtocol;
    source.tags.emplace_back(constants::test::kTestInboundTag);
    source.port = constants::test::kTestPort;
    // The ordinary StreamSettings and SniffConfig defaults are already normalized.
    source.static_users.clients.push_back(StaticUser{
        .id = std::string(constants::test::kTestVmessUuid),
        .password = {}, .email = "test@example.com", .flow = {}});
    return source;
}

PreparedStartupInbound PrepareInbound(
    const StaticInboundConfig& source) {
    const auto tag = source.tags.empty()
        ? naming::BuildProtocolPortTag(source.protocol, source.port)
        : source.tags.front();
    StaticInboundRuntimeEntry entry{
        .protocol = source.protocol,
        .tag = tag,
        .all_tags = source.tags.empty()
            ? std::vector<std::string>{tag}
            : source.tags,
        .port = source.port,
        .listen = source.listen,
        .stream_settings = source.stream_settings,
        .sniffing = source.sniffing,
        .proxy_protocol = source.proxy_protocol,
        .outbound_policy = source.outbound_tag
            ? routing::OutboundSelectionPolicy{routing::ForceOutbound(*source.outbound_tag)}
            : (source.routing_enabled
                ? routing::OutboundSelectionPolicy{routing::RouteWithFallback(
                    std::string(constants::protocol::kDirect))}
                : routing::OutboundSelectionPolicy{routing::ForceOutbound(
                    std::string(constants::protocol::kDirect))}),
        .build_request = {},
    };

    if (!proxyman::inbound::HasProxy(entry.protocol)) {
        throw std::invalid_argument(
            "static inbound '" + entry.tag + "' has unsupported protocol '" +
            entry.protocol + "'");
    }

    auto build_request = proxyman::inbound::PrepareBuildRequest(
        entry.protocol,
        entry.tag,
        source.static_users);
    if (!build_request) {
        throw std::invalid_argument(
            "static inbound '" + entry.tag +
            "' has invalid protocol settings");
    }
    entry.build_request = std::move(*build_request);

    auto users = proxyman::inbound::BuildStaticUsers(
        entry.protocol,
        entry.tag,
        source.static_users);
    if (!users) {
        throw std::invalid_argument(
            "static inbound '" + entry.tag + "' has invalid users or settings");
    }
    if (proxyman::inbound::UserSetEmpty(*users)) {
        throw std::invalid_argument(
            "static inbound '" + entry.tag + "' has no valid users");
    }

    TransportSecurity::Prepare(entry.stream_settings, StreamEndpointRole::Inbound);

    return PreparedStartupInbound{
        .runtime = std::move(entry),
        .users = std::move(*users),
    };
}

}  // namespace

std::vector<PreparedStartupInbound> PrepareStartupInbounds(
    std::vector<StaticInboundConfig> sources, bool enable_test_mode) {
    if (enable_test_mode) sources.push_back(MakeTestInboundConfig());
    const auto validation = ValidateStaticInboundSemantics(sources);
    if (!validation.Ok()) {
        throw std::invalid_argument("startup inbound " + validation.Message());
    }
    std::vector<PreparedStartupInbound> prepared;
    prepared.reserve(sources.size());
    for (const auto& source : sources) {
        prepared.push_back(PrepareInbound(source));
    }

    return prepared;
}

}  // namespace acpp
