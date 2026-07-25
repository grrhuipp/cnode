#include "inboundbuilder.hpp"
#include "tls_policy.hpp"

#include "acppnode/app/proxyman/inbound/factory.hpp"
#include "acppnode/core/constants.hpp"
#include "acppnode/core/naming.hpp"
#include "acppnode/infra/config_types.hpp"

#include <stdexcept>

namespace acpp::controller {

namespace {

std::string ResolveNodeTag(const std::string& panel_name, const api::NodeInfo& config) {
    return naming::BuildPanelNodeTag(
        panel_name,
        naming::ResolveProtocolOrDefault(config.NodeType),
        config.Port);
}

}  // namespace

InboundBuild InboundBuilder(const std::string& panel_name,
                            const PanelConfig* panel_config,
                            const api::NodeInfo& node_config) {
    InboundBuild build;
    build.protocol = naming::ResolveProtocolOrDefault(node_config.NodeType);
    build.tag = ResolveNodeTag(panel_name, node_config);

    build.stream_settings.network = node_config.TransportProtocol.empty()
        ? std::string(constants::protocol::kTcp)
        : node_config.TransportProtocol;

    // TLSEnable only declares that this cnode instance can terminate TLS.
    // The panel node still decides whether this particular inbound uses TLS.
    const bool tls_enable = ShouldEnableInboundTls(panel_config, node_config);

    if (panel_config) {
        build.proxy_protocol = panel_config->ProxyProtocol;
    }

    if (tls_enable) {
        build.stream_settings.security = std::string(constants::protocol::kTls);
        if (panel_config) {
            build.stream_settings.tls.cert_file = panel_config->TLSCert;
            build.stream_settings.tls.key_file = panel_config->TLSKey;
        }
        build.stream_settings.tls.server_name = node_config.TLSServerName;
    }

    build.stream_settings.RecomputeModes();

    if (build.stream_settings.IsWs()) {
        build.stream_settings.ws.path = node_config.Path.empty()
            ? std::string(constants::binding::kRootPath)
            : node_config.Path;
        if (!node_config.Host.empty()) {
            build.stream_settings.ws.headers["Host"] = node_config.Host;
        }
    }
    if (build.stream_settings.IsHttpUpgrade()) {
        build.stream_settings.http_upgrade.path = node_config.Path.empty()
            ? std::string(constants::binding::kRootPath)
            : node_config.Path;
        if (!node_config.Host.empty()) {
            build.stream_settings.http_upgrade.host = node_config.Host;
        }
    }
    build.stream_settings.RecomputeModes();

    build.sniff.enabled = node_config.SniffEnabled;
    build.sniff.dest_override = node_config.DestOverride;

    StaticUserConfig protocol_source;
    protocol_source.method = node_config.CypherMethod.empty()
        ? std::string(constants::protocol::kAes256Gcm)
        : node_config.CypherMethod;
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

    build.binding = MakePortBinding(
        node_config.Port,
        build.protocol,
        build.tag,
        panel_config ? panel_config->ListenIP
                     : InboundListen{});

    return build;
}

}  // namespace acpp::controller
