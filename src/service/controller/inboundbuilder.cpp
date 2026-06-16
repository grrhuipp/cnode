#include "inboundbuilder.hpp"

#include "acppnode/core/constants.hpp"
#include "acppnode/core/naming.hpp"

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

    std::string cert_file = node_config.TLSCert;
    std::string key_file = node_config.TLSKey;
    bool tls_enable = node_config.EnableTLS;

    if (panel_config) {
        tls_enable = panel_config->TLSEnable;
        if (tls_enable) {
            if (!panel_config->TLSCert.empty()) cert_file = panel_config->TLSCert;
            if (!panel_config->TLSKey.empty()) key_file = panel_config->TLSKey;
        }
        build.proxy_protocol = panel_config->ProxyProtocol;
    }

    if (tls_enable) {
        build.stream_settings.security = std::string(constants::protocol::kTls);
        build.stream_settings.tls.cert_file = cert_file;
        build.stream_settings.tls.key_file = key_file;
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

    build.handler_request.tag = build.tag;
    build.handler_request.protocol = build.protocol;
    build.handler_request.cipher_method = node_config.CypherMethod.empty()
        ? std::string(constants::protocol::kAes256Gcm)
        : node_config.CypherMethod;

    build.binding = MakePortBinding(
        node_config.Port,
        build.protocol,
        build.tag,
        panel_config ? panel_config->ListenIP
                     : std::string(constants::network::kDualStackAuto));

    return build;
}

}  // namespace acpp::controller
