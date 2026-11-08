#include "infra/panel_config.hpp"

#include "common/domain_name.hpp"
#include "common/ip_utils.hpp"
#include "core/naming.hpp"
#include "infra/json_field.hpp"
#include "infra/proxy_protocol_config.hpp"
#include "infra/log.hpp"
#include "transport/internet/http_headers.hpp"
#include "transport/internet/tls_config.hpp"
#include "transport/internet/tls_stream.hpp"

#include <charconv>
#include <filesystem>
#include <format>
#include <limits>
#include <optional>
#include <stdexcept>
#include <string_view>
#include <utility>


namespace {

std::optional<uint16_t> ParsePanelHttpPort(std::string_view value) noexcept {
    uint32_t parsed = 0;
    const auto [end, ec] = std::from_chars(
        value.data(), value.data() + value.size(), parsed);
    if (value.empty() || ec != std::errc{} ||
        end != value.data() + value.size() || parsed == 0 ||
        parsed > std::numeric_limits<uint16_t>::max()) {
        return std::nullopt;
    }
    return static_cast<uint16_t>(parsed);
}

}  // namespace

bool IsValidPanelName(std::string_view name) noexcept {
    if (name.empty()) {
        return false;
    }
    for (const unsigned char ch : name) {
        if (ch < 0x20 || ch == 0x7f || ch == '/' || ch == '\\') {
            return false;
        }
    }
    return true;
}

bool IsValidPanelKey(std::string_view key) noexcept {
    if (key.empty()) {
        return false;
    }
    for (const unsigned char ch : key) {
        if (ch <= 0x20 || ch == 0x7f || ch == '?' || ch == '#' || ch == '&') {
            return false;
        }
    }
    return true;
}

std::optional<PanelApiUrlParts> ParsePanelApiUrl(std::string_view url) {
    const size_t scheme_pos = url.find("://");
    if (scheme_pos == std::string_view::npos) {
        return std::nullopt;
    }
    const std::string_view scheme = url.substr(0, scheme_pos);
    const bool is_http =
        transport::internet::EqualsAsciiCI(scheme, constants::protocol::kHttp);
    const bool is_https =
        transport::internet::EqualsAsciiCI(scheme, constants::protocol::kHttps);
    if (!is_http && !is_https) {
        return std::nullopt;
    }
    const bool use_ssl = is_https;
    const std::string_view rest = url.substr(scheme_pos + 3);
    const size_t path_pos = rest.find('/');
    const std::string_view authority = path_pos == std::string_view::npos
        ? rest
        : rest.substr(0, path_pos);
    std::string_view path_prefix = path_pos == std::string_view::npos
        ? std::string_view{}
        : rest.substr(path_pos);

    if (!transport::internet::IsValidHttpAuthority(authority)) {
        return std::nullopt;
    }
    for (const unsigned char ch : path_prefix) {
        if (ch <= 0x20 || ch == 0x7f || ch == '?' || ch == '#') {
            return std::nullopt;
        }
    }

    std::string_view host;
    std::string_view explicit_port;
    bool has_explicit_port = false;
    if (authority.front() == '[') {
        const size_t close_bracket = authority.find(']');
        if (close_bracket == std::string_view::npos) {
            return std::nullopt;
        }
        host = authority.substr(1, close_bracket - 1);
        if (close_bracket + 1 < authority.size()) {
            if (authority[close_bracket + 1] != ':') {
                return std::nullopt;
            }
            has_explicit_port = true;
            explicit_port = authority.substr(close_bracket + 2);
        }
    } else {
        const size_t first_colon = authority.find(':');
        const size_t last_colon = authority.rfind(':');
        if (first_colon != std::string_view::npos && first_colon == last_colon) {
            host = authority.substr(0, first_colon);
            has_explicit_port = true;
            explicit_port = authority.substr(last_colon + 1);
        } else {
            host = authority;
        }
    }

    if (host.empty()) {
        return std::nullopt;
    }
    uint16_t port = use_ssl ? 443 : 80;
    if (has_explicit_port) {
        const auto parsed_port = ParsePanelHttpPort(explicit_port);
        if (!parsed_port) {
            return std::nullopt;
        }
        port = *parsed_port;
    }

    const auto literal_address = iputil::ParseLiteral(host);
    if (authority.front() == '[') {
        if (!literal_address || !literal_address->is_v6()) {
            return std::nullopt;
        }
    } else if (host.find(':') != std::string_view::npos ||
               (!literal_address &&
                !domain::IsValidDnsHostname(host, domain::TrailingDotPolicy::Allow))) {
        return std::nullopt;
    }
    std::string normalized_host(host);
    if (!literal_address) {
        domain::NormalizeDnsHostnameInPlace(normalized_host);
        if (iputil::ParseLiteral(normalized_host).has_value()) {
            return std::nullopt;
        }
    }

    while (!path_prefix.empty() && path_prefix.back() == '/') {
        path_prefix.remove_suffix(1);
    }

    return PanelApiUrlParts{
        .host = std::move(normalized_host),
        .port = port,
        .path_prefix = std::string(path_prefix),
        .use_ssl = use_ssl,
    };
}
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
    cfg.Type = JsonStringOr(j, "type", constants::panel::kV2BoardType);
    if (transport::internet::EqualsAsciiCI(cfg.Type, constants::panel::kV2BoardType)) {
        cfg.Type = std::string(constants::panel::kV2BoardType);
    }
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

    cfg.NodeType = naming::LowerAscii(
        JsonStringOr(j, "nodeType", constants::panel::kDefaultNodeType));

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
    if (cfg.TLSEnable) {
        if (cfg.TLSCert.empty() != cfg.TLSKey.empty()) {
            throw std::invalid_argument(
                "Panel TLSCert and TLSKey must be configured together");
        }
        if (!cfg.TLSCert.empty()) {
            TlsConfig tls;
            tls.cert_file = cfg.TLSCert;
            tls.key_file = cfg.TLSKey;
            LoadTlsPemMaterial(tls);
            if (!SslContext::CreateServer(tls)) {
                throw std::invalid_argument(
                    "Panel TLS certificate or private key is invalid");
            }
            cfg.TLSPem = std::move(tls.pem);
        }
    }
    return cfg;
}

bool PanelConfig::Validate() const {
    const PanelLogContext log_context{Name, APIHost, NodeIDs.Empty() ? 0 : NodeIDs.Front(), NodeType};
    if (RequestTimeout <= std::chrono::seconds::zero() ||
        RequestTimeout > std::chrono::seconds(defaults::kMaxPanelRequestTimeout)) {
        LOG_PANEL_ERROR(log_context, "Panel RequestTimeout must be between 1 and {} seconds",
                        defaults::kMaxPanelRequestTimeout);
        return false;
    }
    if (Name.empty()) {
        LOG_PANEL_ERROR(log_context, "Panel name is required");
        return false;
    }
    if (!IsValidPanelName(Name)) {
        LOG_PANEL_ERROR(log_context, "Panel name must not contain control characters");
        return false;
    }
    if (APIHost.empty()) {
        LOG_PANEL_ERROR(log_context, "Panel ApiHost is required");
        return false;
    }
    if (!ParsePanelApiUrl(APIHost)) {
        LOG_PANEL_ERROR(log_context, "Panel ApiHost is invalid");
        return false;
    }
    if (Key.empty()) {
        LOG_PANEL_ERROR(log_context, "Panel ApiKey is required");
        return false;
    }
    if (!IsValidPanelKey(Key)) {
        LOG_PANEL_ERROR(log_context, "Panel ApiKey contains invalid characters");
        return false;
    }
    if (NodeIDs.Empty()) {
        LOG_PANEL_ERROR(log_context, "Panel NodeIDs is required");
        return false;
    }
    if (Type != constants::panel::kV2BoardType) {
        LOG_PANEL_ERROR(log_context, "Panel Type must be {}", constants::panel::kV2BoardType);
        return false;
    }
    if (NodeType != constants::protocol::kVmess &&
        NodeType != constants::protocol::kVless &&
        NodeType != constants::protocol::kTrojan &&
        NodeType != constants::protocol::kShadowsocks &&
        NodeType != constants::protocol::kAnyTLS &&
        NodeType != constants::protocol::kHysteria &&
        NodeType != constants::protocol::kHysteria2) {
        LOG_PANEL_ERROR(log_context,
                  "Panel NodeType must be {}, {}, {}, {}, {}, {} or {}",
                  constants::protocol::kVmess,
                  constants::protocol::kVless,
                  constants::protocol::kTrojan,
                  constants::protocol::kShadowsocks,
                  constants::protocol::kAnyTLS,
                  constants::protocol::kHysteria,
                  constants::protocol::kHysteria2);
        return false;
    }
    if (TLSEnable) {
        if (TLSCert.empty() != TLSKey.empty()) {
            LOG_PANEL_ERROR(log_context, "Panel TLSCert and TLSKey must be configured together");
            return false;
        }
        if (!TLSCert.empty() && !TLSPem) {
            TlsConfig tls;
            tls.cert_file = TLSCert;
            tls.key_file = TLSKey;
            try {
                LoadTlsPemMaterial(tls);
            } catch (const std::exception& e) {
                LOG_PANEL_ERROR(log_context, "Panel TLS material is invalid: {}", e.what());
                return false;
            }
            if (!SslContext::CreateServer(tls)) {
                LOG_PANEL_ERROR(log_context, "Panel TLS certificate or private key is invalid");
                return false;
            }
        }
    }
    return true;
}

