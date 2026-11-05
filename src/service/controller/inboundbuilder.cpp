#include "inboundbuilder.hpp"
#include <format>
#include "tls_policy.hpp"

#include "acppnode/app/proxyman/inbound/factory.hpp"
#include "acppnode/core/constants.hpp"
#include "acppnode/core/naming.hpp"
#include "acppnode/infra/config_types.hpp"
#include "acppnode/transport/internet/transport_security.hpp"

#include <stdexcept>

namespace acpp::controller {

InboundBuild InboundBuilder(const PanelConfig& panel_config,
                            const api::NodeInfo& node_config) {
    InboundBuild build;
    build.protocol = node_config.NodeType;
    build.tag = naming::BuildPanelNodeTag(
        panel_config.Name, panel_config.NodeIDs.Front(), build.protocol, node_config.Port);
    build.accounting_key = std::format("panel/{}/{}/",
        panel_config.Name, panel_config.NodeIDs.Front());

    build.stream_settings.network = node_config.TransportProtocol.empty()
        ? std::string(constants::protocol::kTcp)
        : node_config.TransportProtocol;

    // TLSEnable only declares that this cnode instance can terminate TLS.
    // The panel node still decides whether this particular inbound uses TLS.
    const bool tls_enable = ShouldEnableInboundTls(panel_config, node_config);

    build.proxy_protocol = panel_config.ProxyProtocol;

    if (node_config.EnableReality) {
        build.stream_settings.security = std::string(constants::protocol::kReality);
        build.stream_settings.reality = node_config.Reality;
    } else if (tls_enable) {
        build.stream_settings.security = std::string(constants::protocol::kTls);
        build.stream_settings.tls.cert_file = panel_config.TLSCert;
        build.stream_settings.tls.key_file = panel_config.TLSKey;
        build.stream_settings.tls.server_name = node_config.TLSServerName;
        LoadTlsPemMaterial(build.stream_settings.tls);
    }

    // Fill the transport sub-config first: normalization derives cached
    // fields (gRPC request path, XHTTP path, Host) from it.
    switch (ParseNetworkMode(build.stream_settings.network)) {
    case NetworkMode::Ws:
        build.stream_settings.ws.path = node_config.Path.empty()
            ? std::string(constants::binding::kRootPath)
            : node_config.Path;
        if (!node_config.Host.empty()) {
            build.stream_settings.ws.headers["Host"] = node_config.Host;
        }
        break;
    case NetworkMode::HttpUpgrade:
        build.stream_settings.http_upgrade.path = node_config.Path.empty()
            ? std::string(constants::binding::kRootPath)
            : node_config.Path;
        if (!node_config.Host.empty()) {
            build.stream_settings.http_upgrade.host = node_config.Host;
        }
        break;
    case NetworkMode::Grpc:
        build.stream_settings.grpc.service_name = !node_config.ServiceName.empty()
            ? node_config.ServiceName
            : node_config.Path;
        if (!node_config.Host.empty()) {
            build.stream_settings.grpc.authority = node_config.Host;
        }
        break;
    case NetworkMode::XHttp:
        build.stream_settings.xhttp.path = node_config.Path.empty()
            ? std::string(constants::binding::kRootPath)
            : node_config.Path;
        if (!node_config.Host.empty()) {
            build.stream_settings.xhttp.host = node_config.Host;
        }
        break;
    default:
        break;
    }

    build.stream_settings = NormalizeStreamSettings(build.stream_settings);
    if (build.stream_settings.network_mode == NetworkMode::Unsupported ||
        build.stream_settings.security_mode == SecurityMode::Unsupported) {
        throw std::invalid_argument("panel inbound has unsupported stream settings");
    }
    TransportSecurity::Prepare(build.stream_settings, StreamEndpointRole::Inbound);
    build.sniff.enabled = node_config.SniffEnabled;
    build.sniff.dest_override = 0;
    for (const auto& protocol : node_config.DestOverride) {
        const uint8_t bit = SniffConfig::DestOverrideBit(protocol);
        if (bit == 0) {
            throw std::invalid_argument(std::format(
                "panel inbound '{}' has unsupported sniffing destOverride '{}'",
                build.tag, protocol));
        }
        build.sniff.dest_override |= bit;
    }

    StaticUserConfig protocol_source;
    protocol_source.method = node_config.CypherMethod;
    protocol_source.identity_password = node_config.ShadowsocksServerKey;
    auto handler_request = proxyman::inbound::PrepareBuildRequest(
        build.protocol,
        build.tag,
        protocol_source);
    if (!handler_request) {
        throw std::invalid_argument(
            "panel inbound '" + build.tag +
            "' has invalid protocol settings");
    }
    build.handler_request = std::move(*handler_request);

    build.binding = PortBinding{.port = node_config.Port, .protocol = build.protocol, .tag = build.tag, .listen = panel_config.ListenIP};

    return build;
}

}  // namespace acpp::controller
