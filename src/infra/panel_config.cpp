#include "acppnode/infra/panel_config.hpp"

#include "acppnode/core/naming.hpp"
#include "json_bool.hpp"
#include "json_string.hpp"
#include "acppnode/infra/log.hpp"

#include <format>
#include <filesystem>
#include <algorithm>
#include <cctype>
#include <stdexcept>
#include <string_view>
#include <utility>

namespace acpp {

namespace {

inline std::string jstr(const json::object& obj,
                        std::string_view key,
                        std::string_view def = "") {
    auto parsed = ParseJsonString(obj, key);
    if (!parsed) {
        throw std::invalid_argument(std::move(parsed.error()));
    }
    return (*parsed).value_or(std::string(def));
}

inline bool jbool(const json::object& obj,
                  std::string_view key,
                  bool def = false) {
    auto parsed = ParseJsonBool(obj, key);
    if (!parsed) {
        throw std::invalid_argument(std::move(parsed.error()));
    }
    return (*parsed).value_or(def);
}

std::string LowerCopy(std::string_view value) {
    std::string out(value);
    std::ranges::transform(out, out.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return out;
}

ProxyProtocolMode ParseProxyProtocolMode(const json::object& obj,
                                         std::string_view key,
                                         ProxyProtocolMode def) {
    auto* p = obj.if_contains(key);
    if (!p) return def;
    if (!p->is_string()) {
        throw std::invalid_argument("Panel proxyProtocol must be off, auto, or on");
    }

    const auto mode = LowerCopy(p->as_string());
    if (mode == "auto") {
        return ProxyProtocolMode::Auto;
    }
    if (mode == "on") {
        return ProxyProtocolMode::On;
    }
    if (mode == "off") {
        return ProxyProtocolMode::Off;
    }
    throw std::invalid_argument("Panel proxyProtocol must be off, auto, or on");
}

} // anonymous namespace

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
    cfg.Name      = jstr(j, "name");
    cfg.Type      = jstr(j, "type", std::string(constants::panel::kV2BoardType));
    cfg.APIHost   = jstr(j, "apiHost");
    cfg.Key       = jstr(j, "key");

    if (const auto* timeout = j.if_contains("requestTimeout")) {
        uint64_t seconds = 0;
        if (timeout->is_int64() && timeout->as_int64() > 0) {
            seconds = static_cast<uint64_t>(timeout->as_int64());
        } else if (timeout->is_uint64()) {
            seconds = timeout->as_uint64();
        }
        if (seconds == 0 || seconds > defaults::kMaxPanelRequestTimeout) {
            throw std::invalid_argument(std::format(
                "Panel requestTimeout must be an integer between 1 and {} seconds",
                defaults::kMaxPanelRequestTimeout));
        }
        cfg.RequestTimeout = std::chrono::seconds(static_cast<int64_t>(seconds));
    }

    const auto raw_node_type =
        jstr(j, "nodeType", std::string(constants::panel::kDefaultNodeType));
    cfg.NodeType = naming::NormalizePanelNodeProtocol(raw_node_type);

    if (const auto* node_ids = j.if_contains("nodeIDs")) {
        cfg.NodeIDs = PanelNodeIds::Parse(*node_ids);
    }
    if (cfg.Name.empty() && !cfg.NodeIDs.Empty()) {
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
    cfg.EnableDNS = jbool(j, "enableDNS", cfg.EnableDNS);
    cfg.DNSType = jstr(j, "dnsType", cfg.DNSType);
    cfg.ProxyProtocol = ParseProxyProtocolMode(j, "proxyProtocol", cfg.ProxyProtocol);
    cfg.TLSEnable = jbool(j, "tlsEnable", cfg.TLSEnable);
    cfg.TLSCert   = jstr(j, "tlsCert", cfg.TLSCert);
    cfg.TLSKey    = jstr(j, "tlsKey", cfg.TLSKey);
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
