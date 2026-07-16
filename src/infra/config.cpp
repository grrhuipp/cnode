#include "acppnode/infra/config.hpp"
#include "acppnode/core/naming.hpp"
#include "acppnode/infra/json_port.hpp"
#include "acppnode/infra/log.hpp"
#include "http2_initial_window.hpp"
#include "json_bool.hpp"
#include "acppnode/infra/json_object.hpp"
#include "json_string.hpp"
#include "json_unsigned.hpp"
#include <algorithm>
#include <cctype>
#include <charconv>
#include <format>
#include <limits>
#include <optional>
#include <stdexcept>
#include <thread>
#include <utility>

namespace acpp {

// ============================================================================
// JSON 辅助函数
// ============================================================================

namespace {

[[nodiscard]] RoutingIpNetwork RequireRoutingIpNetwork(
    std::string_view value, std::string_view field) {
    auto parsed = RoutingIpNetwork::Parse(value);
    if (!parsed) {
        throw std::invalid_argument(std::format(
            "routing field '{}' contains invalid IP network '{}'", field, value));
    }
    return std::move(*parsed);
}

// 从 object 中取 string，不存在则返回默认值
inline std::string jstr(
    const json::object& obj,
    std::initializer_list<std::string_view> aliases,
    std::string_view def = "") {
    auto parsed = ParseAliasedJsonString(obj, aliases);
    if (!parsed) {
        throw std::invalid_argument(std::move(parsed.error()));
    }
    if (!*parsed) {
        return std::string(def);
    }
    return std::move(**parsed);
}

inline std::string jstr(
    const json::object& obj,
    std::string_view key,
    std::string_view def = "") {
    return jstr(obj, {key}, def);
}

// 从 object 中取 bool，不存在则返回默认值
inline bool jbool(
    const json::object& obj,
    std::initializer_list<std::string_view> aliases,
    bool def = false) {
    auto parsed = ParseAliasedJsonBool(obj, aliases);
    if (!parsed) {
        throw std::invalid_argument(std::move(parsed.error()));
    }
    return parsed->value_or(def);
}

uint32_t juint32(
    const json::object& obj,
    std::initializer_list<std::string_view> aliases,
    uint32_t def) {
    auto parsed = ParseAliasedJsonUint64(
        obj, aliases, std::numeric_limits<uint32_t>::max());
    if (!parsed) {
        throw std::invalid_argument(std::move(parsed.error()));
    }
    return static_cast<uint32_t>(parsed->value_or(def));
}

const json::object* optional_object(
    const json::object& obj,
    std::initializer_list<std::string_view> aliases) {
    auto parsed = ParseAliasedJsonObject(obj, aliases);
    if (!parsed) {
        throw std::invalid_argument(std::move(parsed.error()));
    }
    return *parsed;
}

uint16_t required_port(const json::object& obj, std::string_view key) {
    const auto result = ReadJsonPort(obj, {key});
    switch (result.error) {
        case JsonPortError::None:
            return result.value;
        case JsonPortError::Missing:
            throw std::invalid_argument(std::string(key) + " is required");
        case JsonPortError::InvalidType:
            throw std::invalid_argument(std::string(key) + " must be an integer");
        case JsonPortError::OutOfRange:
            throw std::invalid_argument(
                std::string(key) + " must be between 1 and 65535");
    }
    throw std::invalid_argument(std::string(key) + " is invalid");
}

inline std::vector<std::string> jstr_array(
    const json::object& obj,
    std::initializer_list<std::string_view> aliases) {
    auto parsed = ParseAliasedJsonStringArray(obj, aliases);
    if (!parsed) {
        throw std::invalid_argument(std::move(parsed.error()));
    }
    if (!*parsed) {
        return {};
    }
    return std::move(**parsed);
}

std::string lower_ascii_copy(std::string value) {
    std::ranges::transform(value, value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return value;
}

TlsVersion ParseTlsVersion(
    std::string_view value, std::string_view field) {
    if (value == "1.2") return TlsVersion::V1_2;
    if (value == "1.3") return TlsVersion::V1_3;
    throw std::invalid_argument(std::format(
        "tls {} must be 1.2 or 1.3", field));
}

void require_http_request_target(
    std::string_view value, std::string_view field) {
    if (!value.empty() &&
        !transport::internet::IsValidHttpRequestTarget(value)) {
        throw std::invalid_argument(std::format(
            "{} must be a valid HTTP request target", field));
    }
}

void require_http_authority(
    std::string_view value, std::string_view field) {
    if (!value.empty() && !transport::internet::IsValidHttpAuthority(value)) {
        throw std::invalid_argument(std::format(
            "{} must be a valid HTTP authority", field));
    }
}

void require_http_header_name(
    std::string_view value, std::string_view field) {
    if (!value.empty() && !transport::internet::IsValidHttpHeaderName(value)) {
        throw std::invalid_argument(std::format(
            "{} must be a valid HTTP header name", field));
    }
}

void parse_http_headers(const json::object& j,
                        transport::internet::HttpHeaders& headers,
                        std::string_view key = "headers") {
    const auto* declaration = j.if_contains(key);
    if (!declaration) return;
    if (!declaration->is_object()) {
        throw std::invalid_argument(std::format("{} must be an object", key));
    }
    for (const auto& [name, raw_value] : declaration->as_object()) {
        if (!transport::internet::IsValidHttpHeaderName(name)) {
            throw std::invalid_argument("HTTP header name is invalid");
        }
        if (!raw_value.is_string()) {
            throw std::invalid_argument(std::format(
                "HTTP header '{}' must be a string", name));
        }
        const std::string& value = raw_value.as_string();
        const std::string normalized =
            transport::internet::NormalizeHttpHeaderName(name);
        if (!transport::internet::IsValidHttpHeaderValue(value)) {
            throw std::invalid_argument(std::format(
                "HTTP header '{}' contains invalid control characters",
                normalized));
        }
        if (normalized == "host" &&
            !transport::internet::IsValidHttpAuthority(value)) {
            throw std::invalid_argument(
                "HTTP header 'host' must be a valid HTTP authority");
        }
        const auto [existing, inserted] = headers.emplace(normalized, value);
        if (!inserted && existing->second != value) {
            throw std::invalid_argument(std::format(
                "HTTP header '{}' has conflicting values", normalized));
        }
    }
}

std::string_view TrimRoutingPortToken(std::string_view value) noexcept {
    while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) {
        value.remove_prefix(1);
    }
    while (!value.empty() && (value.back() == ' ' || value.back() == '\t')) {
        value.remove_suffix(1);
    }
    return value;
}

uint16_t ParseRoutingPortNumber(std::string_view value,
                                std::string_view field) {
    value = TrimRoutingPortToken(value);
    uint32_t parsed = 0;
    const auto [end, ec] = std::from_chars(
        value.data(), value.data() + value.size(), parsed);
    if (value.empty() || ec != std::errc{} ||
        end != value.data() + value.size() || parsed == 0 ||
        parsed > std::numeric_limits<uint16_t>::max()) {
        throw std::invalid_argument(std::format(
            "routing {} value '{}' must be an integer between 1 and 65535",
            field, value));
    }
    return static_cast<uint16_t>(parsed);
}

RoutingPortRange ParseRoutingPortRange(std::string_view value,
                                       std::string_view field) {
    value = TrimRoutingPortToken(value);
    const size_t dash = value.find('-');
    if (dash == std::string_view::npos) {
        const uint16_t port = ParseRoutingPortNumber(value, field);
        return {.start = port, .end = port};
    }
    if (dash == 0 || dash + 1 == value.size() ||
        value.find('-', dash + 1) != std::string_view::npos) {
        throw std::invalid_argument(std::format(
            "routing {} port range '{}' is invalid", field, value));
    }

    const uint16_t start = ParseRoutingPortNumber(value.substr(0, dash), field);
    const uint16_t end = ParseRoutingPortNumber(value.substr(dash + 1), field);
    if (start > end) {
        throw std::invalid_argument(std::format(
            "routing {} port range '{}' must be ascending", field, value));
    }
    return {.start = start, .end = end};
}

void AppendRoutingPortText(std::vector<RoutingPortRange>& out,
                           std::string_view text,
                           std::string_view field) {
    size_t start = 0;
    for (;;) {
        const size_t comma = text.find(',', start);
        const size_t end = comma == std::string_view::npos ? text.size() : comma;
        out.push_back(ParseRoutingPortRange(text.substr(start, end - start), field));
        if (comma == std::string_view::npos) {
            return;
        }
        start = comma + 1;
    }
}

void AppendRoutingPortValue(std::vector<RoutingPortRange>& out,
                            const json::value& value,
                            std::string_view field) {
    if (value.is_string()) {
        AppendRoutingPortText(out, value.as_string(), field);
        return;
    }
    if (value.is_int64()) {
        AppendRoutingPortText(out, std::to_string(value.as_int64()), field);
        return;
    }
    if (value.is_uint64()) {
        AppendRoutingPortText(out, std::to_string(value.as_uint64()), field);
        return;
    }
    throw std::invalid_argument(std::format(
        "routing {} must be a port, range, or array of ports and ranges", field));
}

void AppendRoutingPortField(const json::object& object,
                            std::string_view key,
                            std::vector<RoutingPortRange>& out) {
    const auto* value = object.if_contains(key);
    if (!value) {
        return;
    }
    if (value->is_array()) {
        for (const auto& item : value->as_array()) {
            AppendRoutingPortValue(out, item, key);
        }
        return;
    }
    AppendRoutingPortValue(out, *value, key);
}


} // anonymous namespace

// ============================================================================
// LogConfig
// ============================================================================
LogConfig LogConfig::FromJson(const json::object& j) {
    LogConfig cfg;
    auto level = jstr(j, "loglevel");
    if (!level.empty()) cfg.level = level;

    auto dir = jstr(j, "logDir");
    if (!dir.empty()) cfg.log_dir = dir;

    auto access_path = jstr(j, "access");
    if (!access_path.empty()) cfg.access_path = access_path;

    auto error_path = jstr(j, "error");
    if (!error_path.empty()) cfg.error_path = error_path;

    auto days = ParseAliasedJsonUint64(
        j, {"maxDays"}, std::numeric_limits<uint16_t>::max());
    if (!days) {
        throw std::invalid_argument(std::move(days.error()));
    }
    cfg.max_days = static_cast<uint16_t>(days->value_or(cfg.max_days));

    cfg.rotate_daily = jbool(j, {"rotateDaily"}, cfg.rotate_daily);
    cfg.gzip = jbool(j, {"gzip", "compress"}, cfg.gzip);
    return cfg;
}

// ============================================================================
// DnsConfig
// ============================================================================
DnsConfig::DnsConfig()
    : servers{
        net::ip::make_address("8.8.8.8"),
        net::ip::make_address("1.1.1.1"),
    } {}

DnsConfig DnsConfig::FromJson(const json::object& j) {
    DnsConfig cfg;
    if (const auto* servers = j.if_contains("servers")) {
        if (!servers->is_array()) {
            throw std::invalid_argument("dns servers must be an array of IP addresses");
        }
        cfg.servers.clear();
        cfg.servers.reserve(servers->as_array().size());
        for (const auto& server : servers->as_array()) {
            if (!server.is_string()) {
                throw std::invalid_argument("dns server must be an IP address string");
            }
            const auto text = server.as_string();
            IoErrorCode error;
            auto address = net::ip::make_address(text, error);
            if (error) {
                throw std::invalid_argument(std::format(
                    "dns server '{}' is not a valid IP address", text));
            }
            cfg.servers.push_back(std::move(address));
        }
    }
    cfg.timeout    = juint32(j, {"timeout"}, cfg.timeout);
    cfg.cache_size = juint32(j, {"cacheSize"}, cfg.cache_size);
    cfg.min_ttl    = juint32(j, {"minTTL"}, cfg.min_ttl);
    cfg.max_ttl    = juint32(j, {"maxTTL"}, cfg.max_ttl);
    return cfg;
}

// ============================================================================
// LimitsConfig
// ============================================================================
LimitsConfig LimitsConfig::FromJson(const json::object& j) {
    LimitsConfig cfg;
    cfg.max_connections = juint32(
        j, {"maxConnections"}, cfg.max_connections);
    cfg.max_connections_per_ip = juint32(
        j, {"maxConnectionsPerIP"}, cfg.max_connections_per_ip);
    return cfg;
}

// ============================================================================
// TimeoutsConfig
// ============================================================================
TimeoutsConfig TimeoutsConfig::FromJson(const json::object& j) {
    TimeoutsConfig cfg;
    cfg.handshake = juint32(j, {"handshake"}, cfg.handshake);
    cfg.dial = juint32(j, {"dial"}, cfg.dial);
    cfg.read = juint32(j, {"read"}, cfg.read);
    cfg.write = juint32(j, {"write"}, cfg.write);
    cfg.idle = juint32(j, {"connIdle", "idle"}, cfg.idle);
    cfg.uplink_only = juint32(j, {"uplinkOnly"}, cfg.uplink_only);
    cfg.downlink_only = juint32(j, {"downlinkOnly"}, cfg.downlink_only);
    return cfg;
}

// ============================================================================
// RouteRuleConfig
// ============================================================================
RouteRuleConfig RouteRuleConfig::FromJson(const json::object& j) {
    RouteRuleConfig rule;

    // 域名匹配 - 处理 xray 格式 (domain 数组可能包含 geosite:xxx, full:xxx 等)
    if (j.contains("domain")) {
        for (std::string val : jstr_array(j, {"domain"})) {

            // 解析前缀
            if (val.substr(0, 8) == "geosite:") {
                rule.geosite.push_back(val.substr(8));
            } else if (val.substr(0, 5) == "full:") {
                rule.domain_full.push_back(val.substr(5));
            } else if (val.substr(0, 8) == "keyword:") {
                rule.domain_keyword.push_back(val.substr(8));
            } else if (val.substr(0, 7) == "regexp:") {
                rule.domain_regex.push_back(val.substr(7));
            } else if (val.substr(0, 7) == "domain:") {
                rule.domain_suffix.push_back(val.substr(7));
            } else {
                // 默认作为后缀匹配
                rule.domain_suffix.push_back(val);
            }
        }
    }

    // 独立的域名字段
    if (j.contains("domainSuffix") || j.contains("domain_suffix")) {
        auto arr = jstr_array(j, {"domainSuffix", "domain_suffix"});
        rule.domain_suffix.insert(rule.domain_suffix.end(), arr.begin(), arr.end());
    }
    if (j.contains("domainKeyword") || j.contains("domain_keyword")) {
        auto arr = jstr_array(j, {"domainKeyword", "domain_keyword"});
        rule.domain_keyword.insert(rule.domain_keyword.end(), arr.begin(), arr.end());
    }
    if (j.contains("domainFull") || j.contains("domain_full")) {
        auto arr = jstr_array(j, {"domainFull", "domain_full"});
        rule.domain_full.insert(rule.domain_full.end(), arr.begin(), arr.end());
    }
    if (j.contains("domainRegex") || j.contains("domainRegexp") ||
        j.contains("domain_regex") || j.contains("domain_regexp")) {
        auto arr = jstr_array(j, {
            "domainRegex", "domainRegexp", "domain_regex", "domain_regexp"});
        rule.domain_regex.insert(rule.domain_regex.end(), arr.begin(), arr.end());
    }
    if (j.contains("geosite")) {
        auto arr = jstr_array(j, {"geosite"});
        rule.geosite.insert(rule.geosite.end(), arr.begin(), arr.end());
    }

    // IP 匹配 - 处理 xray 格式 (ip 数组可能包含 geoip:xxx)
    if (j.contains("ip")) {
        for (std::string val : jstr_array(j, {"ip"})) {

            if (val.substr(0, 6) == "geoip:") {
                rule.geoip.push_back(val.substr(6));
            } else {
                rule.ip.push_back(RequireRoutingIpNetwork(val, "ip"));
            }
        }
    }
    if (j.contains("geoip")) {
        auto arr = jstr_array(j, {"geoip"});
        rule.geoip.insert(rule.geoip.end(), arr.begin(), arr.end());
    }

    // 辅助：将逗号分隔的字符串拆为 vector
    auto split_comma = [](const std::string& s) -> std::vector<std::string> {
        std::vector<std::string> result;
        size_t start = 0;
        while (start < s.size()) {
            auto pos = s.find(',', start);
            if (pos == std::string::npos) pos = s.size();
            auto token = s.substr(start, pos - start);
            // 去除首尾空格
            auto b = token.find_first_not_of(' ');
            auto e = token.find_last_not_of(' ');
            if (b != std::string::npos) {
                result.push_back(token.substr(b, e - b + 1));
            }
            start = pos + 1;
        }
        return result;
    };

    // 辅助：解析字符串/整数/数组字段，支持逗号分隔字符串（Xray 格式）
    auto parse_str_or_array = [&](std::string_view key) -> std::vector<std::string> {
        auto* p = j.if_contains(key);
        if (!p) return {};
        if (p->is_array()) return jstr_array(j, {key});
        if (p->is_string()) return split_comma(std::string(p->as_string()));
        if (p->is_int64()) return {std::to_string(p->as_int64())};
        if (p->is_uint64()) return {std::to_string(p->as_uint64())};
        throw std::invalid_argument(std::format(
            "routing {} must be a string, integer, or array of strings", key));
    };

    // 端口（支持 Xray 格式: "53,443,1000-2000"）
    AppendRoutingPortField(j, "port", rule.port);

    // 网络类型（支持 Xray 格式: "tcp,udp"）
    {
        auto vals = parse_str_or_array("network");
        rule.network.insert(rule.network.end(), vals.begin(), vals.end());
    }

    // 入站标签
    {
        auto vals = parse_str_or_array("inboundTag");
        rule.inbound_tag.insert(rule.inbound_tag.end(), vals.begin(), vals.end());
        vals = parse_str_or_array("inbound_tag");
        rule.inbound_tag.insert(rule.inbound_tag.end(), vals.begin(), vals.end());
    }

    // 用户 email（Xray user 字段）
    {
        auto vals = parse_str_or_array("user");
        rule.user.insert(rule.user.end(), vals.begin(), vals.end());
    }

    // 来源 IP/CIDR（Xray source 字段）
    if (j.contains("source") && j.at("source").is_array()) {
        for (const auto& value : jstr_array(j, {"source"})) {
            rule.source.push_back(RequireRoutingIpNetwork(value, "source"));
        }
    } else {
        auto vals = parse_str_or_array("source");
        for (const auto& value : vals) {
            rule.source.push_back(RequireRoutingIpNetwork(value, "source"));
        }
    }

    // 来源端口（Xray sourcePort 字段）
    AppendRoutingPortField(j, "sourcePort", rule.source_port);
    AppendRoutingPortField(j, "source_port", rule.source_port);

    // 嗅探协议（Xray protocol 字段）
    {
        auto vals = parse_str_or_array("protocol");
        rule.protocol.insert(rule.protocol.end(), vals.begin(), vals.end());
    }

    // 目标出站
    if (j.contains("outboundTag")) {
        rule.outbound_tag = std::string(j.at("outboundTag").as_string());
    } else if (j.contains("outbound_tag")) {
        rule.outbound_tag = std::string(j.at("outbound_tag").as_string());
    }

    return rule;
}

// ============================================================================
// RoutingConfig
// ============================================================================
RoutingConfig RoutingConfig::FromJson(const json::object& j) {
    RoutingConfig cfg;
    if (j.contains("domainStrategy")) {
        cfg.domain_strategy = std::string(j.at("domainStrategy").as_string());
    } else if (j.contains("domain_strategy")) {
        cfg.domain_strategy = std::string(j.at("domain_strategy").as_string());
    }
    if (j.contains("rules")) {
        for (const auto& rule : j.at("rules").as_array()) {
            cfg.rules.push_back(RouteRuleConfig::FromJson(rule.as_object()));
        }
    }
    return cfg;
}

// ============================================================================
// WsConfig / StreamSettings
// ============================================================================

WsConfig WsConfig::FromJson(const json::object& j) {
    WsConfig cfg;
    cfg.path = jstr(j, "path", std::string(constants::binding::kRootPath));
    require_http_request_target(cfg.path, "ws path");
    parse_http_headers(j, cfg.headers);
    cfg.real_ip_header = jstr(j, {"realIpHeader", "real_ip_header"}, "");
    require_http_header_name(cfg.real_ip_header, "ws realIpHeader");
    return cfg;
}

HttpUpgradeConfig HttpUpgradeConfig::FromJson(const json::object& j) {
    HttpUpgradeConfig cfg;
    cfg.path = jstr(j, "path", std::string(constants::binding::kRootPath));
    cfg.host = jstr(j, "host", "");
    require_http_request_target(cfg.path, "http upgrade path");
    require_http_authority(cfg.host, "http upgrade host");
    parse_http_headers(j, cfg.headers);
    cfg.real_ip_header = jstr(j, {"realIpHeader", "real_ip_header"}, "");
    require_http_header_name(
        cfg.real_ip_header, "http upgrade realIpHeader");
    cfg.accept_proxy_protocol = jbool(j, {"acceptProxyProtocol"}, false);
    return cfg;
}

HttpConfig HttpConfig::FromJson(const json::object& j) {
    HttpConfig cfg;
    cfg.path = jstr(j, "path", std::string(constants::binding::kRootPath));
    cfg.host = jstr(j, "host", "");
    cfg.method = jstr(j, "method", "");
    require_http_request_target(cfg.path, "http path");
    require_http_authority(cfg.host, "http host");
    if (!cfg.method.empty() &&
        !transport::internet::IsValidHttpHeaderName(cfg.method)) {
        throw std::invalid_argument("http method must be a valid HTTP token");
    }
    parse_http_headers(j, cfg.headers);
    cfg.real_ip_header = jstr(j, {"realIpHeader", "real_ip_header"}, "");
    require_http_header_name(cfg.real_ip_header, "http realIpHeader");
    cfg.force_http2 = jbool(j, {"forceHttp2", "force_http2"}, false);
    auto initial_window = ParseHttp2InitialWindow(j);
    if (!initial_window) {
        throw std::invalid_argument(std::move(initial_window.error()));
    }
    cfg.initial_window_size = *initial_window;
    return cfg;
}

GrpcConfig GrpcConfig::FromJson(const json::object& j) {
    GrpcConfig cfg;
    cfg.authority = jstr(j, {"authority", "host"}, "");
    cfg.service_name = jstr(j, {"serviceName", "service_name"}, "");
    cfg.user_agent = jstr(j, {"userAgent", "user_agent"}, "");
    cfg.multi_mode = jbool(j, {"multiMode", "multi_mode"}, false);
    require_http_authority(cfg.authority, "grpc authority");
    require_http_request_target(cfg.RequestPath(), "grpc serviceName path");
    if (!transport::internet::IsValidHttpHeaderValue(cfg.user_agent)) {
        throw std::invalid_argument(
            "grpc userAgent contains invalid control characters");
    }
    if (j.contains("initial_windows_size")) {
        throw std::invalid_argument(
            "initial_windows_size is not supported; use initial_window_size");
    }
    auto initial_window = ParseHttp2InitialWindow(j);
    if (!initial_window) {
        throw std::invalid_argument(std::move(initial_window.error()));
    }
    cfg.initial_window_size = *initial_window;
    return cfg;
}

std::shared_ptr<const XHttpDownloadSettings> ParseXHttpDownloadSettings(
    const json::object& j) {
    auto settings = std::make_shared<XHttpDownloadSettings>();

    std::optional<std::string> address;
    std::string_view address_key;
    for (const std::string_view key : {"address", "server"}) {
        const auto* value = j.if_contains(key);
        if (!value) continue;
        if (!value->is_string() || value->as_string().empty()) {
            throw std::invalid_argument(std::format(
                "xhttp download {} must be a non-empty string", key));
        }
        const std::string parsed(value->as_string());
        if (address && *address != parsed) {
            throw std::invalid_argument(std::format(
                "xhttp download {} and {} must match", address_key, key));
        }
        if (!address) {
            address = parsed;
            address_key = key;
        }
    }
    if (!address) {
        throw std::invalid_argument("xhttp download address is required");
    }
    settings->address = std::move(*address);

    std::optional<uint16_t> port;
    std::string_view port_key;
    for (const std::string_view key : {"port", "server_port"}) {
        if (!j.contains(key)) continue;
        const auto parsed = ReadJsonPort(j, {key});
        if (!parsed.Valid()) {
            throw std::invalid_argument(std::format(
                "xhttp download {} must be an integer between 1 and 65535", key));
        }
        if (port && *port != parsed.value) {
            throw std::invalid_argument(std::format(
                "xhttp download {} and {} must match", port_key, key));
        }
        if (!port) {
            port = parsed.value;
            port_key = key;
        }
    }
    if (!port) throw std::invalid_argument("xhttp download port is required");
    settings->port = *port;

    std::optional<std::string> send_through;
    std::string_view bind_key;
    for (const std::string_view key : {"sendThrough", "send_through"}) {
        const auto* value = j.if_contains(key);
        if (!value) continue;
        if (!value->is_string()) {
            throw std::invalid_argument(std::format(
                "xhttp download {} must be a string", key));
        }
        const std::string parsed(value->as_string());
        if (send_through && *send_through != parsed) {
            throw std::invalid_argument(std::format(
                "xhttp download {} and {} must match", bind_key, key));
        }
        if (!send_through) {
            send_through = parsed;
            bind_key = key;
        }
    }
    auto parsed_bind = OutboundBind::Parse(send_through.value_or(""));
    if (!parsed_bind) {
        throw std::invalid_argument(std::format(
            "xhttp download sendThrough '{}' must be auto, wildcard, or an IP address",
            send_through.value_or("")));
    }
    settings->send_through = std::move(*parsed_bind);

    settings->stream_settings = StreamSettings::FromJson(
        j, StreamEndpointRole::Outbound);
    if (settings->stream_settings.xhttp.download_settings) {
        throw std::invalid_argument("nested xhttp downloadSettings is not supported");
    }
    if (!settings->stream_settings.IsXHttp()) {
        throw std::invalid_argument("xhttp download network must be xhttp");
    }
    if (settings->stream_settings.xhttp.IsStreamOne()) {
        throw std::invalid_argument(
            "xhttp download mode stream-one is not supported");
    }
    if (!settings->stream_settings.xhttp.AcceptsPacketUp() &&
        !settings->stream_settings.xhttp.AcceptsStreamUp()) {
        throw std::invalid_argument(std::format(
            "xhttp download mode '{}' is not supported",
            settings->stream_settings.xhttp.mode));
    }
    return settings;
}

XHttpConfig XHttpConfig::FromJson(const json::object& j) {
    XHttpConfig cfg;
    cfg.path = jstr(j, "path", std::string(constants::binding::kRootPath));
    cfg.host = jstr(j, "host", "");
    cfg.mode = lower_ascii_copy(jstr(j, "mode", ""));
    require_http_request_target(cfg.path, "xhttp path");
    require_http_authority(cfg.host, "xhttp host");
    parse_http_headers(j, cfg.headers);
    cfg.no_grpc_header = jbool(j, {"noGRPCHeader", "no_grpc_header"}, false);
    cfg.no_sse_header = jbool(j, {"noSSEHeader", "no_sse_header"}, false);
    auto parse_download_settings = [&](const json::object& source) {
        const json::value* declaration = nullptr;
        std::string_view declaration_key;
        for (const std::string_view key : {"downloadSettings", "download_settings"}) {
            const auto* value = source.if_contains(key);
            if (!value) continue;
            if (declaration) {
                throw std::invalid_argument(
                    "xhttp downloadSettings must be declared only once");
            }
            declaration = value;
            declaration_key = key;
        }
        if (!declaration) return;
        if (!declaration->is_object()) {
            throw std::invalid_argument(std::format(
                "xhttp {} must be an object", declaration_key));
        }
        if (cfg.download_settings) {
            throw std::invalid_argument(
                "xhttp downloadSettings must be declared only once");
        }
        cfg.download_settings =
            ParseXHttpDownloadSettings(declaration->as_object());
    };
    parse_download_settings(j);
    if (const auto* extra = optional_object(j, {"extra"})) {
        parse_http_headers(*extra, cfg.headers);
        cfg.no_grpc_header = jbool(
            *extra, {"noGRPCHeader", "no_grpc_header"}, cfg.no_grpc_header);
        cfg.no_sse_header = jbool(
            *extra, {"noSSEHeader", "no_sse_header"}, cfg.no_sse_header);
        parse_download_settings(*extra);
    }
    if (cfg.download_settings) {
        if (cfg.IsStreamOne()) {
            throw std::invalid_argument(
                "xhttp upload mode stream-one cannot use downloadSettings");
        }
        if (!cfg.AcceptsPacketUp() && !cfg.AcceptsStreamUp()) {
            throw std::invalid_argument(std::format(
                "xhttp upload mode '{}' cannot use downloadSettings", cfg.mode));
        }
    }
    return cfg;
}

RealityConfig RealityConfig::FromJson(const json::object& j) {
    RealityConfig cfg;
    cfg.show = jbool(j, {"show"}, false);
    cfg.type = lower_ascii_copy(jstr(j, "type", ""));
    if (j.contains("dest") || j.contains("target")) {
        throw std::invalid_argument(
            "REALITY dest/target is not supported; target fallback for "
            "unauthenticated handshakes is not implemented");
    }
    auto xver = ParseAliasedJsonUint64(j, {"xver"}, 2);
    if (!xver) {
        throw std::invalid_argument(std::move(xver.error()));
    }
    if (xver->value_or(0) != 0) {
        throw std::invalid_argument(
            "REALITY xver 1 and 2 are not supported; PROXY protocol forwarding "
            "to the REALITY target is not implemented");
    }
    cfg.server_names = jstr_array(j, {"serverNames", "server_names"});
    cfg.private_key = jstr(j, {"privateKey", "private_key"}, "");
    cfg.short_ids = jstr_array(j, {"shortIds", "short_ids"});
    cfg.min_client_ver = jstr(j, {"minClientVer", "min_client_ver"}, "");
    cfg.max_client_ver = jstr(j, {"maxClientVer", "max_client_ver"}, "");
    auto max_time_diff = ParseAliasedJsonUint64(
        j, {"maxTimeDiff", "max_time_diff"});
    if (!max_time_diff) {
        throw std::invalid_argument(std::move(max_time_diff.error()));
    }
    cfg.max_time_diff = max_time_diff->value_or(0);
    if (j.contains("mldsa65Seed") || j.contains("mldsa65_seed") ||
        j.contains("mldsa65Verify") || j.contains("mldsa65_verify")) {
        throw std::invalid_argument(
            "REALITY ML-DSA-65 certificate signing and verification are not "
            "supported");
    }
    if (j.contains("fingerprint")) {
        throw std::invalid_argument(
            "REALITY fingerprint is not supported; ClientHello fingerprint "
            "emulation is not implemented");
    }
    cfg.server_name = jstr(j, {"serverName", "server_name"}, "");
    cfg.public_key = jstr(
        j, {"publicKey", "public_key", "password"}, "");
    cfg.short_id = jstr(j, {"shortId", "short_id"}, "");
    if (j.contains("spiderX") || j.contains("spider_x")) {
        throw std::invalid_argument(
            "REALITY spiderX/spider_x is not supported; the REALITY crawler "
            "is not implemented");
    }
    cfg.master_key_log = jstr(
        j, {"masterKeyLog", "master_key_log"}, "");
    return cfg;
}

std::string XHttpConfig::NormalizedPath() const {
    std::string normalized = path.empty()
        ? std::string(constants::binding::kRootPath)
        : path;
    const size_t query_pos = normalized.find('?');
    if (query_pos != std::string::npos) {
        normalized.erase(query_pos);
    }
    if (normalized.empty() || normalized.front() != '/') {
        normalized.insert(normalized.begin(), '/');
    }
    if (normalized.back() != '/') {
        normalized.push_back('/');
    }
    return normalized;
}

bool XHttpConfig::IsStreamOne() const noexcept {
    return mode == "stream-one";
}

bool XHttpConfig::AcceptsStreamOne() const noexcept {
    return mode.empty() ||
           mode == "auto" ||
           mode == "stream-one" ||
           mode == "stream-up";
}

bool XHttpConfig::AcceptsPacketUp() const noexcept {
    return mode.empty() ||
           mode == "auto" ||
           mode == "packet-up";
}

bool XHttpConfig::AcceptsStreamUp() const noexcept {
    return mode.empty() ||
           mode == "auto" ||
           mode == "stream-up";
}

std::string GrpcConfig::RequestPath() const {
    if (!service_name.empty() && service_name.front() == '/') {
        return service_name;
    }
    std::string path;
    path.reserve(service_name.size() + 10);
    path.push_back('/');
    path.append(service_name);
    path.append(multi_mode ? "/TunMulti" : "/Tun");
    return path;
}

StreamSettings StreamSettings::FromJson(
    const json::object& j, StreamEndpointRole role) {
    StreamSettings cfg;
    bool min_version_declared = false;
    bool max_version_declared = false;

    cfg.network  = lower_ascii_copy(
        jstr(j, "network",  std::string(constants::protocol::kTcp)));
    cfg.security = lower_ascii_copy(
        jstr(j, "security", std::string(constants::protocol::kNone)));

    // TLS 配置
    if (const auto* tls = optional_object(j, {"tlsSettings"})) {
        min_version_declared =
            tls->contains("minVersion") || tls->contains("min_version");
        max_version_declared =
            tls->contains("maxVersion") || tls->contains("max_version");
        cfg.tls.min_version = ParseTlsVersion(
            jstr(*tls, {"minVersion", "min_version"}, "1.2"),
            "minVersion");
        cfg.tls.max_version = ParseTlsVersion(
            jstr(*tls, {"maxVersion", "max_version"}, "1.3"),
            "maxVersion");
        if (cfg.tls.min_version > cfg.tls.max_version) {
            throw std::invalid_argument(
                "tls minVersion must not exceed maxVersion");
        }
        cfg.tls.server_name = jstr(*tls, "serverName", "");
        cfg.tls.allow_insecure = jbool(*tls, {"allowInsecure"}, false);
        cfg.tls.ca_file = jstr(*tls, {"caFile", "ca_file"}, "");
        if (role == StreamEndpointRole::Inbound &&
            cfg.tls.allow_insecure) {
            throw std::invalid_argument(
                "inbound tls allowInsecure is not supported");
        }
        if (role == StreamEndpointRole::Inbound &&
            !cfg.tls.ca_file.empty()) {
            throw std::invalid_argument(
                "inbound tls caFile is not supported");
        }
        if (cfg.tls.allow_insecure && !cfg.tls.ca_file.empty()) {
            throw std::invalid_argument(
                "tls caFile cannot be used with allowInsecure");
        }
        // ALPN
        cfg.tls.alpn = jstr_array(*tls, {"alpn"});
        std::optional<std::pair<std::string, std::string>> certificate_entry;
        if (const auto* certificates = tls->if_contains("certificates")) {
            if (!certificates->is_array()) {
                throw std::invalid_argument(
                    "tls certificates must be an array");
            }
            if (certificates->as_array().size() > 1) {
                throw std::invalid_argument(
                    "multiple TLS certificates are not supported");
            }
            if (!certificates->as_array().empty()) {
                const auto& entry = certificates->as_array()[0];
                if (!entry.is_object()) {
                    throw std::invalid_argument(
                        "tls certificates entries must be objects");
                }
                std::string cert_file = jstr(
                    entry.as_object(), "certificateFile", "");
                std::string key_file = jstr(
                    entry.as_object(), "keyFile", "");
                if (cert_file.empty() || key_file.empty()) {
                    throw std::invalid_argument(
                        "tls certificates entry must provide certificateFile "
                        "and keyFile");
                }
                certificate_entry.emplace(
                    std::move(cert_file), std::move(key_file));
            }
        }

        std::string direct_cert_file = jstr(*tls, "certFile", "");
        std::string direct_key_file = jstr(*tls, "keyFile", "");
        if (direct_cert_file.empty() != direct_key_file.empty()) {
            throw std::invalid_argument(
                "tls certFile and keyFile must be configured together");
        }
        if (certificate_entry && !direct_cert_file.empty() &&
            (certificate_entry->first != direct_cert_file ||
             certificate_entry->second != direct_key_file)) {
            throw std::invalid_argument(
                "tls certificates and certFile/keyFile must match");
        }
        if (certificate_entry) {
            cfg.tls.cert_file = std::move(certificate_entry->first);
            cfg.tls.key_file = std::move(certificate_entry->second);
        } else {
            cfg.tls.cert_file = std::move(direct_cert_file);
            cfg.tls.key_file = std::move(direct_key_file);
        }
    }

    if (const auto* reality = optional_object(
            j, {"realitySettings", "reality_settings"})) {
        cfg.reality = RealityConfig::FromJson(*reality);
    }
    if (cfg.security == constants::protocol::kReality) {
        if ((min_version_declared &&
             cfg.tls.min_version != TlsVersion::V1_3) ||
            (max_version_declared &&
             cfg.tls.max_version != TlsVersion::V1_3)) {
            throw std::invalid_argument(
                "reality requires TLS minVersion and maxVersion 1.3");
        }
        cfg.tls.min_version = TlsVersion::V1_3;
        cfg.tls.max_version = TlsVersion::V1_3;
    }
    if (cfg.tls.server_name.empty() && !cfg.reality.server_name.empty()) {
        cfg.tls.server_name = cfg.reality.server_name;
    }

    // WS 配置
    if (const auto* ws = optional_object(
            j, {"wsSettings", "websocketSettings"})) {
        cfg.ws = WsConfig::FromJson(*ws);
    }

    if (const auto* http_upgrade = optional_object(
            j, {"httpupgradeSettings", "httpUpgradeSettings"})) {
        cfg.http_upgrade = HttpUpgradeConfig::FromJson(*http_upgrade);
    }

    if (const auto* http = optional_object(
            j, {"httpSettings", "h2Settings", "http_settings"})) {
        cfg.http = HttpConfig::FromJson(*http);
    }

    if (const auto* grpc = optional_object(
            j, {"grpcSettings", "grpc_settings"})) {
        cfg.grpc = GrpcConfig::FromJson(*grpc);
    }

    if (const auto* xhttp = optional_object(j, {
            "xhttpSettings", "splithttpSettings",
            "xhttp_settings", "splithttp_settings"})) {
        cfg.xhttp = XHttpConfig::FromJson(*xhttp);
    }

    cfg.RecomputeModes();
    return cfg;
}

void StreamSettings::RecomputeModes() noexcept {
    // 仅初始化/配置更新时调用，热路径不再做字符串比较
    network = lower_ascii_copy(std::move(network));
    security = lower_ascii_copy(std::move(security));

    if (network.empty() ||
        network == constants::protocol::kTcp ||
        network == constants::protocol::kRaw) {
        network_mode = NetworkMode::Tcp;
    } else if (network == constants::protocol::kWs ||
               network == constants::protocol::kWebSocket) {
        network_mode = NetworkMode::Ws;
    } else if (network == constants::protocol::kHttpUpgrade ||
               network == "httpupgrade") {
        network_mode = NetworkMode::HttpUpgrade;
        network = std::string(constants::protocol::kHttpUpgrade);
    } else if (network == constants::protocol::kGrpc) {
        network_mode = NetworkMode::Grpc;
    } else if (network == constants::protocol::kHttp || network == "h2") {
        http.force_http2 = http.force_http2 || (network == "h2");
        network_mode = NetworkMode::Http;
    } else if (network == constants::protocol::kXHttp || network == "splithttp") {
        network_mode = NetworkMode::XHttp;
    } else {
        network_mode = NetworkMode::Unsupported;
    }

    if (security.empty() || security == constants::protocol::kNone) {
        security_mode = SecurityMode::None;
    } else if (security == constants::protocol::kTls) {
        security_mode = SecurityMode::Tls;
    } else if (security == constants::protocol::kReality) {
        security_mode = SecurityMode::Reality;
        tls.min_version = TlsVersion::V1_3;
        tls.max_version = TlsVersion::V1_3;
    } else {
        security_mode = SecurityMode::Unsupported;
    }

    flags = kFlagNone;
    if (network_mode == NetworkMode::Ws) {
        flags |= kFlagWs;
    }
    if (network_mode == NetworkMode::HttpUpgrade) {
        flags |= kFlagHttpUpgrade;
    }
    if (network_mode == NetworkMode::Grpc) {
        flags |= kFlagGrpc;
        network = std::string(constants::protocol::kGrpc);
    }
    if (network_mode == NetworkMode::Http) {
        flags |= kFlagHttp;
        network = http.force_http2 ? "h2" : std::string(constants::protocol::kHttp);
    }
    if (network_mode == NetworkMode::XHttp) {
        flags |= kFlagXHttp;
        network = std::string(constants::protocol::kXHttp);
    }
    if (security_mode == SecurityMode::Tls) {
        flags |= kFlagTls;
    }
    if (security_mode == SecurityMode::Reality) {
        flags |= kFlagReality;
    }

    const bool tls_like_for_alpn = IsTls();
    const bool http_should_default_h2 =
        network_mode == NetworkMode::Http &&
        (http.force_http2 ||
         (tls_like_for_alpn && tls.alpn.empty()));
    const bool xhttp_should_default_h2 =
        network_mode == NetworkMode::XHttp &&
        security_mode != SecurityMode::Reality &&
        (xhttp.AcceptsStreamOne() || tls_like_for_alpn) &&
        tls.alpn.empty();
    if ((network_mode == NetworkMode::Grpc && tls_like_for_alpn) ||
        http_should_default_h2 ||
        xhttp_should_default_h2) {
        auto has_h2 = std::ranges::find(tls.alpn, "h2") != tls.alpn.end();
        if (!has_h2) {
            tls.alpn.insert(tls.alpn.begin(), "h2");
        }
    }
}

// ============================================================================
// StaticInboundConfig
// ============================================================================
namespace {

StaticUserConfig ParseStaticUserConfig(
    std::string_view protocol,
    const json::object& settings) {
    StaticUserConfig config;
    config.method = jstr(settings, "method", config.method);
    if (protocol == constants::protocol::kVless) {
        config.vless_decryption = jstr(
            settings,
            "decryption",
            std::string(constants::protocol::kNone));
    }
    std::optional<std::string> padding_scheme;
    std::string_view padding_key;
    for (const std::string_view key : {"paddingScheme", "padding_scheme"}) {
        const auto* padding = settings.if_contains(key);
        if (!padding) continue;

        std::string parsed;
        if (padding->is_string()) {
            parsed = std::string(padding->as_string());
        } else if (padding->is_array()) {
            bool first = true;
            for (const auto& item : padding->as_array()) {
                if (!item.is_string()) {
                    throw std::invalid_argument(std::format(
                        "{} must contain only strings", key));
                }
                if (!first) {
                    parsed.push_back('\n');
                }
                parsed.append(item.as_string());
                first = false;
            }
        } else {
            throw std::invalid_argument(std::format(
                "{} must be a string or array of strings", key));
        }
        if (padding_scheme && *padding_scheme != parsed) {
            throw std::invalid_argument(std::format(
                "{} and {} must match", padding_key, key));
        }
        if (!padding_scheme) {
            padding_scheme = std::move(parsed);
            padding_key = key;
        }
    }
    config.padding_scheme = std::move(padding_scheme).value_or("");

    const bool ss2022_method = config.method.rfind("2022-", 0) == 0;
    StaticUser top_level_user;
    if (protocol == constants::protocol::kShadowsocks ||
        protocol == constants::protocol::kTrojan ||
        protocol == constants::protocol::kAnyTLS) {
        top_level_user.password = jstr(settings, "password", "");
        if (protocol == constants::protocol::kShadowsocks) {
            config.identity_password = top_level_user.password;
        }
        top_level_user.email = jstr(settings, "email", "");
    }

    auto parse_user_arrays = [&](std::initializer_list<std::string_view> aliases)
            -> std::optional<std::vector<StaticUser>> {
        std::optional<std::vector<StaticUser>> parsed;
        std::string_view first_key;
        for (const std::string_view key : aliases) {
            const auto* users = settings.if_contains(key);
            if (!users) continue;
            if (!users->is_array()) {
                throw std::invalid_argument(std::format(
                    "{} must be an array", key));
            }

            std::vector<StaticUser> candidates;
            candidates.reserve(users->as_array().size());
            for (const auto& client : users->as_array()) {
                if (!client.is_object()) {
                    throw std::invalid_argument(std::format(
                        "{} entries must be objects", key));
                }
                const auto& client_obj = client.as_object();

                StaticUser user;
                user.id = jstr(client_obj, {"id", "uuid"}, "");
                user.password = jstr(client_obj, "password", "");
                user.email = jstr(client_obj, "email", "");
                user.flow = jstr(client_obj, "flow", "");
                candidates.push_back(std::move(user));
            }

            auto users_match = [](const StaticUser& lhs, const StaticUser& rhs) {
                return lhs.id == rhs.id &&
                       lhs.password == rhs.password &&
                       lhs.email == rhs.email &&
                       lhs.flow == rhs.flow;
            };
            if (parsed &&
                (parsed->size() != candidates.size() ||
                 !std::ranges::equal(*parsed, candidates, users_match))) {
                throw std::invalid_argument(std::format(
                    "{} and {} must match", first_key, key));
            }
            if (!parsed) {
                parsed = std::move(candidates);
                first_key = key;
            }
        }
        return parsed;
    };

    std::optional<std::vector<StaticUser>> users;
    if (protocol == constants::protocol::kAnyTLS) {
        users = parse_user_arrays({"users", "clients"});
    } else if (protocol == constants::protocol::kVless) {
        users = parse_user_arrays({"clients", "users"});
    } else {
        users = parse_user_arrays({"clients"});
    }
    const bool saw_user_array = users && !users->empty();
    if (users) {
        config.clients = std::move(*users);
    }

    if (protocol == constants::protocol::kShadowsocks &&
        !top_level_user.password.empty() &&
        (!ss2022_method || !saw_user_array)) {
        config.clients.insert(config.clients.begin(), std::move(top_level_user));
    } else if ((protocol == constants::protocol::kTrojan ||
                protocol == constants::protocol::kAnyTLS) &&
               !top_level_user.password.empty() &&
               !saw_user_array) {
        config.clients.insert(config.clients.begin(), std::move(top_level_user));
    }

    return config;
}

}  // namespace

StaticInboundConfig StaticInboundConfig::FromJson(const json::object& j) {
    StaticInboundConfig cfg;

    // tag 支持字符串或数组（多标签匹配任一）
    auto parse_tag = [&](std::string_view key) {
        auto* p = j.if_contains(key);
        if (!p) return;
        if (p->is_string()) {
            cfg.tags.push_back(std::string(p->as_string()));
        } else if (p->is_array()) {
            for (const auto& item : p->as_array()) {
                if (item.is_string()) {
                    cfg.tags.push_back(std::string(item.as_string()));
                }
            }
        }
    };
    parse_tag("tag");

    if (j.contains("protocol")) {
        cfg.protocol = std::string(j.at("protocol").as_string());
    }

    if (j.contains("listen")) {
        if (!j.at("listen").is_string()) {
            throw std::invalid_argument("static inbound listen must be a string");
        }
        auto listen = InboundListen::Parse(j.at("listen").as_string());
        if (!listen) {
            throw std::invalid_argument(std::format(
                "static inbound listen '{}' must be auto or an IP address",
                j.at("listen").as_string()));
        }
        cfg.listen = std::move(*listen);
    }

    cfg.port = required_port(j, "port");

    if (const auto* settings = optional_object(j, {"settings"})) {
        cfg.static_users = ParseStaticUserConfig(cfg.protocol, *settings);
    }

    if (const auto* stream_settings = optional_object(
            j, {"streamSettings", "stream_settings"})) {
        cfg.stream_settings = StreamSettings::FromJson(
            *stream_settings, StreamEndpointRole::Inbound);
    }

    // Xray sniffing 配置
    if (const auto* sniffing = optional_object(j, {"sniffing"})) {
        cfg.sniffing.enabled = jbool(*sniffing, {"enabled"}, true);
        cfg.sniffing.dest_override =
            jstr_array(*sniffing, {"destOverride", "dest_override"});
        cfg.sniffing.domains_excluded =
            jstr_array(*sniffing, {"domainsExcluded", "domains_excluded"});
    }

    cfg.routing_enabled = jbool(
        j, {"routingEnabled", "routing_enabled"}, cfg.routing_enabled);

    return cfg;
}

// ============================================================================
// Config
// ============================================================================

std::optional<Config> Config::LoadFromJson(const json::object& j) {
    Config cfg;

    try {
        if (const auto* log = optional_object(j, {"log"})) {
            cfg.log_ = LogConfig::FromJson(*log);
        }

        cfg.workers_ = juint32(j, {"workers"}, cfg.workers_);
        if (cfg.workers_ > defaults::kMaxWorkers) {
            throw std::invalid_argument(std::format(
                "workers must be between 0 and {}", defaults::kMaxWorkers));
        }

        if (const auto* dns = optional_object(j, {"dns"})) {
            cfg.dns_ = DnsConfig::FromJson(*dns);
        }

        if (const auto* limits = optional_object(j, {"limits"})) {
            cfg.limits_ = LimitsConfig::FromJson(*limits);
        }

        if (const auto* timeouts = optional_object(j, {"timeouts"})) {
            cfg.timeouts_ = TimeoutsConfig::FromJson(*timeouts);
        }

        auto parse_panels = [&](std::string_view key) {
            if (!j.contains(key)) return;
            const auto& arr = j.at(key);
            if (!arr.is_array()) {
                throw std::invalid_argument(
                    std::format("{} must be an array", key));
            }
            for (const auto& panel : arr.as_array()) {
                if (!panel.is_object()) {
                    throw std::runtime_error("panel entry must be an object");
                }
                cfg.panels_.push_back(PanelConfig::FromJson(panel.as_object()));
            }
        };
        parse_panels("panels");

        // Workers 默认值
        if (cfg.workers_ == 0) {
            cfg.workers_ = std::thread::hardware_concurrency();
            if (cfg.workers_ == 0) {
                cfg.workers_ = 1;  // 至少 1 个
            }
        }

        return cfg;

    } catch (const std::exception& e) {
        LOG_ERROR("Failed to parse config: {}", e.what());
        return std::nullopt;
    }
}

}  // namespace acpp
