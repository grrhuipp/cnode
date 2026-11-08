#include "panel_inbound.hpp"
#include "tls_policy.hpp"

#include "core/constants.hpp"
#include "core/naming.hpp"
#include "features/routing/dispatch_policy.hpp"
#include "transport/internet/http_headers.hpp"
#include "transport/internet/tls_config.hpp"

#include <stdexcept>

namespace controller {

namespace {

[[nodiscard]] StreamSettings MapPanelStreamSettings(
    const PanelConfig& panel_config,
    const api::NodeInfo& node_config) {
    StreamSettings stream;
    stream.network = node_config.TransportProtocol.empty()
        ? std::string(constants::protocol::kTcp)
        : node_config.TransportProtocol;

    // TLSEnable only declares that this cnode instance can terminate TLS.
    // The panel node still decides whether this particular inbound uses TLS.
    if (node_config.EnableReality) {
        stream.security = std::string(constants::protocol::kReality);
        stream.reality = node_config.Reality;
    } else if (ShouldEnableInboundTls(panel_config, node_config)) {
        stream.security = std::string(constants::protocol::kTls);
        stream.tls.cert_file = panel_config.TLSCert;
        stream.tls.key_file = panel_config.TLSKey;
        stream.tls.server_name = node_config.TLSServerName;
        stream.tls.pem = panel_config.TLSPem;
        if (!stream.tls.pem) {
            LoadTlsPemMaterial(stream.tls);
        }
    }

    // Fill the transport sub-config first: normalization derives cached
    // fields (gRPC request path, XHTTP path, Host) from it.
    switch (ParseNetworkMode(stream.network)) {
    case NetworkMode::Ws:
        stream.ws.path = node_config.Path;
        if (!node_config.Host.empty()) {
            stream.ws.headers.emplace(
                transport::internet::NormalizeHttpHeaderName("Host"),
                node_config.Host);
        }
        break;
    case NetworkMode::HttpUpgrade:
        stream.http_upgrade.path = node_config.Path;
        stream.http_upgrade.host = node_config.Host;
        break;
    case NetworkMode::Http:
        stream.http.path = node_config.Path;
        stream.http.host = node_config.Host;
        break;
    case NetworkMode::Grpc:
        stream.grpc.service_name = node_config.ServiceName;
        stream.grpc.authority = node_config.Host;
        break;
    case NetworkMode::XHttp:
        stream.xhttp.path = node_config.Path;
        stream.xhttp.host = node_config.Host;
        break;
    default:
        break;
    }

    stream = NormalizeStreamSettings(stream);
    if (stream.network_mode == NetworkMode::Unsupported ||
        stream.security_mode == SecurityMode::Unsupported) {
        throw std::invalid_argument("panel inbound has unsupported stream settings");
    }
    return stream;
}

}  // namespace

std::vector<InboundUserSpec> MapPanelUsers(
    const api::NodeInfo& node_config,
    std::span<const api::UserInfo> users) {
    std::vector<InboundUserSpec> specs;
    specs.reserve(users.size());
    for (const auto& user : users) {
        specs.push_back(InboundUserSpec{
            .user_id = user.UID,
            .email = user.Email,
            .credential = user.UUID,
            .flow = user.Flow.empty() ? node_config.Flow : user.Flow,
            .speed_limit = user.SpeedLimit,
            .device_limit = user.DeviceLimit,
        });
    }
    return specs;
}

InboundSpec MapPanelInbound(
    const PanelConfig& panel_config,
    const api::NodeInfo& node_config,
    std::span<const api::UserInfo> users) {
    const int node_id = panel_config.NodeIDs.Front();
    std::string tag = naming::BuildPanelNodeTag(
        panel_config.Name, node_id, node_config.NodeType, node_config.Port);
    std::vector<std::string> all_tags{tag, std::string(constants::protocol::kNode)};
    routing::OutboundSelectionPolicy outbound_policy{routing::RouteWithFallback(tag)};
    return InboundSpec{
        .tag = std::move(tag),
        .all_tags = std::move(all_tags),
        .accounting_key = naming::BuildPanelNodeAccountingKey(panel_config.Name, node_id),
        .protocol = node_config.NodeType,
        .listen = panel_config.ListenIP,
        .port = node_config.Port,
        .proxy_protocol = panel_config.ProxyProtocol,
        .settings = InboundProtocolSettings{
            .method = node_config.CypherMethod,
            .identity_password = node_config.ShadowsocksServerKey,
            .ss2022_user_key = Ss2022UserKey::UuidDerived,
            .padding_scheme = node_config.PaddingScheme,
            .vless_decryption = std::string(constants::protocol::kNone),
            .hysteria_up_mbps = node_config.HysteriaUpMbps,
            .hysteria_down_mbps = node_config.HysteriaDownMbps,
        },
        .users = MapPanelUsers(node_config, users),
        .stream_settings = MapPanelStreamSettings(panel_config, node_config),
        .sniffing = node_config.Sniffing,
        .outbound_policy = std::move(outbound_policy),
    };
}

}  // namespace controller
