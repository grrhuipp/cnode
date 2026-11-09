#include "app/prepared_inbound.hpp"

#include "infra/config.hpp"
#include "app/proxyman/inbound/factory.hpp"
#include "core/constants.hpp"
#include "core/naming.hpp"
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

namespace {

StaticInboundConfig MakeTestInboundConfig() {
    StaticInboundConfig source;
    source.protocol = constants::protocol::kDefaultNodeProtocol;
    source.tags.emplace_back(constants::test::kTestInboundTag);
    source.port = constants::test::kTestPort;
    // The ordinary StreamSettings and SniffConfig defaults are already normalized.
    source.users.push_back(InboundUserSpec{
        .user_id = 0,
        .email = "test@example.com",
        .credential = std::string(constants::test::kTestVmessUuid),
        .flow = {},
        .speed_limit = 0,
        .device_limit = 0,
    });
    return source;
}

// Static-only mapping: tag fallback, outbound selection and the per-user
// email default. Everything else passes through unchanged.
InboundSpec StaticInboundSpec(StaticInboundConfig source) {
    std::string tag = source.tags.empty()
        ? naming::BuildProtocolPortTag(source.protocol, source.port)
        : source.tags.front();
    std::vector<std::string> all_tags = source.tags.empty()
        ? std::vector<std::string>{tag}
        : std::move(source.tags);
    routing::OutboundSelectionPolicy outbound_policy = source.outbound_tag
        ? routing::OutboundSelectionPolicy{routing::ForceOutbound(*source.outbound_tag)}
        : (source.routing_enabled
            ? routing::OutboundSelectionPolicy{routing::RouteWithFallback(
                std::string(constants::protocol::kDirect))}
            : routing::OutboundSelectionPolicy{routing::ForceOutbound(
                std::string(constants::protocol::kDirect))});
    if (source.protocol == constants::protocol::kAnyTLS ||
        source.protocol == constants::protocol::kHysteria ||
        source.protocol == constants::protocol::kHysteria2) {
        for (auto& user : source.users) {
            if (user.email.empty()) user.email = tag;
        }
    }
    return InboundSpec{
        .tag = std::move(tag),
        .all_tags = std::move(all_tags),
        .accounting_key = {},
        .protocol = std::move(source.protocol),
        .listen = std::move(source.listen),
        .port = source.port,
        .proxy_protocol = source.proxy_protocol,
        .settings = std::move(source.settings),
        .users = std::move(source.users),
        .stream_settings = std::move(source.stream_settings),
        .sniffing = std::move(source.sniffing),
        .outbound_policy = std::move(outbound_policy),
    };
}

}  // namespace

std::vector<PreparedInbound> PrepareStartupInbounds(
    std::vector<StaticInboundConfig> sources, bool enable_test_mode) {
    if (enable_test_mode) sources.push_back(MakeTestInboundConfig());
    const auto validation = ValidateStaticInboundSemantics(sources);
    if (!validation.Ok()) {
        throw std::invalid_argument("startup inbound " + validation.Message());
    }
    std::vector<PreparedInbound> prepared;
    prepared.reserve(sources.size());
    for (auto& source : sources) {
        auto inbound = PrepareInbound(StaticInboundSpec(std::move(source)));
        if (proxyman::inbound::UserSetEmpty(*inbound.users)) {
            throw std::invalid_argument(
                "static inbound '" + inbound.binding.tag + "' has no valid users");
        }
        prepared.push_back(std::move(inbound));
    }

    return prepared;
}

