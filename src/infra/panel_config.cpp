#include "acppnode/infra/panel_config.hpp"

#include "acppnode/core/naming.hpp"
#include "acppnode/infra/json_field.hpp"
#include "acppnode/infra/proxy_protocol_config.hpp"
#include "acppnode/infra/log.hpp"

#include <filesystem>
#include <format>
#include <stdexcept>
#include <string_view>
#include <utility>

namespace acpp {

PanelConfig PanelConfig::FromJson(const json::object& j) {
    static constexpr std::string_view kLegacyKeys[] = {
        "api_host", "request_timeout", "node_type", "node_ids",
        "listen_ip", "send_ip", "enable_dns", "dns_type",
        "proxy_protocol", "tls_enable", "tls_cert", "tls_key",
    };
    for (const std::string_view key : kLegacyKeys) {
        if (j.contains(key)) {
            throw std::invalid_argument(std::format(
                "Panel config key '{}' is not supported; use keys without underscores",
                key));
        }
    }

    PanelConfig cfg;
    cfg.Name      = JsonStringOr(j, "name", "");
    if (j.contains("name") && cfg.Name.empty()) {
        throw std::invalid_argument("Panel name must not be empty");
    }
    cfg.Type      = JsonStringOr(j, "type", constants::panel::kV2BoardType);
    cfg.APIHost   = JsonStringOr(j, "apiHost", "");
    cfg.Key       = JsonStringOr(j, "key", "");

    if (const auto* timeout = j.if_contains("requestTimeout")) {
        const auto seconds = JsonUnsignedInteger(*timeout);
        if (!seconds || *seconds == 0 || *seconds > defaults::kMaxPanelRequestTimeout) {
            throw std::invalid_argument(std::format(
                "Panel requestTimeout must be an integer between 1 and {} seconds",
                defaults::kMaxPanelRequestTimeout));
        }
        cfg.RequestTimeout = std::chrono::seconds(static_cast<int64_t>(*seconds));
    }

    cfg.NodeType = JsonStringOr(j, "nodeType", constants::panel::kDefaultNodeType);

    if (const auto* node_ids = j.if_contains("nodeIDs")) {
        cfg.NodeIDs = PanelNodeIds::Parse(*node_ids);
    }
    if (!j.contains("name") && !cfg.NodeIDs.Empty()) {
        cfg.Name = std::format("{}-{}", cfg.NodeType, cfg.NodeIDs.Front());
    }
    if (const auto* listen_ip = j.if_contains("listenIP")) {
        if (!listen_ip->is_string()) {
            throw std::invalid_argument("Panel listenIP must be a string");
        }
        auto parsed = InboundListen::Parse(listen_ip->as_string());
        if (!parsed) {
            throw std::invalid_argument(std::format(
                "Panel listenIP '{}' must be auto or an IP address",
                listen_ip->as_string()));
        }
        cfg.ListenIP = std::move(*parsed);
    }
    if (const auto* send_ip = j.if_contains("sendIP")) {
        if (!send_ip->is_string()) {
            throw std::invalid_argument("Panel sendIP must be a string");
        }
        auto parsed = OutboundBind::Parse(send_ip->as_string());
        if (!parsed) {
            throw std::invalid_argument(std::format(
                "Panel sendIP '{}' must be auto, wildcard, or an IP address",
                send_ip->as_string()));
        }
        cfg.SendIP = std::move(*parsed);
    }
    cfg.EnableDNS = JsonBoolOr(j, "enableDNS", cfg.EnableDNS);
    if (const auto* value = j.if_contains("dnsType")) {
        if (!value->is_string()) {
            throw std::invalid_argument("Panel dnsType must be a domain strategy string");
        }
        const auto strategy =
            proxy::freedom::outbound::ParseDomainStrategy(value->as_string());
        if (!strategy) {
            throw std::invalid_argument("Panel dnsType is not a supported domain strategy");
        }
        cfg.DNSType = *strategy;
    }
    cfg.ProxyProtocol = ParseProxyProtocolMode(j, "proxyProtocol", cfg.ProxyProtocol);
    cfg.TLSEnable = JsonBoolOr(j, "tlsEnable", cfg.TLSEnable);
    cfg.TLSCert   = JsonStringOr(j, "tlsCert", cfg.TLSCert);
    cfg.TLSKey    = JsonStringOr(j, "tlsKey", cfg.TLSKey);
    return cfg;
}

bool PanelConfig::Validate() const {
    if (RequestTimeout <= std::chrono::seconds::zero() ||
        RequestTimeout > std::chrono::seconds(defaults::kMaxPanelRequestTimeout)) {
        LOG_ERROR("Panel {} RequestTimeout must be between 1 and {} seconds",
                  Name, defaults::kMaxPanelRequestTimeout);
        return false;
    }
    if (Name.empty()) {
        LOG_ERROR("Panel name is required");
        return false;
    }
    if (APIHost.empty()) {
        LOG_ERROR("Panel {} ApiHost is required", Name);
        return false;
    }
    if (Key.empty()) {
        LOG_ERROR("Panel {} ApiKey is required", Name);
        return false;
    }
    if (NodeIDs.Empty()) {
        LOG_ERROR("Panel {} NodeIDs is required", Name);
        return false;
    }
    if (Type != constants::panel::kV2BoardType) {
        LOG_ERROR("Panel {} Type must be {}", Name, constants::panel::kV2BoardType);
        return false;
    }
    if (NodeType != constants::protocol::kVmess &&
        NodeType != constants::protocol::kVless &&
        NodeType != constants::protocol::kTrojan &&
        NodeType != constants::protocol::kShadowsocks &&
        NodeType != constants::protocol::kAnyTLS) {
        LOG_ERROR("Panel {} NodeType must be {}, {}, {}, {} or {}",
                  Name,
                  constants::protocol::kVmess,
                  constants::protocol::kVless,
                  constants::protocol::kTrojan,
                  constants::protocol::kShadowsocks,
                  constants::protocol::kAnyTLS);
        return false;
    }
    if (TLSEnable) {
        if (TLSCert.empty() != TLSKey.empty()) {
            LOG_ERROR("Panel {} TLSCert and TLSKey must be configured together", Name);
            return false;
        }
        if (!TLSCert.empty() && !std::filesystem::exists(TLSCert)) {
            LOG_ERROR("Panel {} TlsCert not found: {}", Name, TLSCert);
            return false;
        }
        if (!TLSKey.empty() && !std::filesystem::exists(TLSKey)) {
            LOG_ERROR("Panel {} TlsKey not found: {}", Name, TLSKey);
            return false;
        }
    }
    return true;
}

}  // namespace acpp
