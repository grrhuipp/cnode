#include "acppnode/infra/config.hpp"
#include "acppnode/core/naming.hpp"
#include "acppnode/infra/json_port.hpp"
#include "acppnode/infra/log.hpp"
#include "http2_initial_window.hpp"
#include "json_bool.hpp"
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

uint32_t juint32(const json::object& obj,
                 std::string_view key,
                 uint32_t def) {
    const auto* value = obj.if_contains(key);
    if (!value) {
        return def;
    }

    uint64_t parsed = 0;
    if (value->is_int64()) {
        const int64_t signed_value = value->as_int64();
        if (signed_value < 0) {
            throw std::invalid_argument(std::format(
                "{} must be an integer between 0 and {}",
                key, std::numeric_limits<uint32_t>::max()));
        }
        parsed = static_cast<uint64_t>(signed_value);
    } else if (value->is_uint64()) {
        parsed = value->as_uint64();
    } else {
        throw std::invalid_argument(std::format(
            "{} must be an integer between 0 and {}",
            key, std::numeric_limits<uint32_t>::max()));
    }

    if (parsed > std::numeric_limits<uint32_t>::max()) {
        throw std::invalid_argument(std::format(
            "{} must be an integer between 0 and {}",
            key, std::numeric_limits<uint32_t>::max()));
    }
    return static_cast<uint32_t>(parsed);
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

// 从 JSON array 中提取 string vector
inline std::vector<std::string> jstr_array(const json::value& v) {
    std::vector<std::string> result;
    if (v.is_array()) {
        for (const auto& item : v.as_array()) {
            if (item.is_string()) {
                result.push_back(std::string(item.as_string()));
            }
        }
    }
    return result;
}

std::string lower_ascii_copy(std::string value) {
    std::ranges::transform(value, value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return value;
}

void parse_http_headers(const json::object& j,
                        transport::internet::HttpHeaders& headers,
                        std::string_view key = "headers") {
    auto* p = j.if_contains(key);
    if (p && p->is_object()) {
        for (const auto& [k, v] : p->as_object()) {
            if (v.is_string()) {
                headers[std::string(k)] = std::string(v.as_string());
            }
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
    cfg.timeout    = juint32(j, "timeout", cfg.timeout);
    cfg.cache_size = juint32(j, "cacheSize", cfg.cache_size);
    cfg.min_ttl    = juint32(j, "minTTL", cfg.min_ttl);
    cfg.max_ttl    = juint32(j, "maxTTL", cfg.max_ttl);
    return cfg;
}

// ============================================================================
// LimitsConfig
// ============================================================================
LimitsConfig LimitsConfig::FromJson(const json::object& j) {
    LimitsConfig cfg;
    cfg.max_connections = juint32(
        j, "maxConnections", cfg.max_connections);
    cfg.max_connections_per_ip = juint32(
        j, "maxConnectionsPerIP", cfg.max_connections_per_ip);
    return cfg;
}

// ============================================================================
// TimeoutsConfig
// ============================================================================
TimeoutsConfig TimeoutsConfig::FromJson(const json::object& j) {
    TimeoutsConfig cfg;
    cfg.handshake = juint32(j, "handshake", cfg.handshake);
    cfg.dial = juint32(j, "dial", cfg.dial);
    cfg.read = juint32(j, "read", cfg.read);
    cfg.write = juint32(j, "write", cfg.write);
    cfg.idle = juint32(j, "connIdle", cfg.idle);
    cfg.idle = juint32(j, "idle", cfg.idle);
    cfg.uplink_only = juint32(j, "uplinkOnly", cfg.uplink_only);
    cfg.downlink_only = juint32(j, "downlinkOnly", cfg.downlink_only);
    return cfg;
}

// ============================================================================
// RouteRuleConfig
// ============================================================================
RouteRuleConfig RouteRuleConfig::FromJson(const json::object& j) {
    RouteRuleConfig rule;

    // 域名匹配 - 处理 xray 格式 (domain 数组可能包含 geosite:xxx, full:xxx 等)
    if (j.contains("domain") && j.at("domain").is_array()) {
        for (const auto& item : j.at("domain").as_array()) {
            std::string val = std::string(item.as_string());

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
    if (j.contains("domainSuffix")) {
        auto arr = jstr_array(j.at("domainSuffix"));
        rule.domain_suffix.insert(rule.domain_suffix.end(), arr.begin(), arr.end());
    }
    if (j.contains("domain_suffix")) {
        auto arr = jstr_array(j.at("domain_suffix"));
        rule.domain_suffix.insert(rule.domain_suffix.end(), arr.begin(), arr.end());
    }
    if (j.contains("domainKeyword")) {
        auto arr = jstr_array(j.at("domainKeyword"));
        rule.domain_keyword.insert(rule.domain_keyword.end(), arr.begin(), arr.end());
    }
    if (j.contains("domain_keyword")) {
        auto arr = jstr_array(j.at("domain_keyword"));
        rule.domain_keyword.insert(rule.domain_keyword.end(), arr.begin(), arr.end());
    }
    if (j.contains("domainFull")) {
        auto arr = jstr_array(j.at("domainFull"));
        rule.domain_full.insert(rule.domain_full.end(), arr.begin(), arr.end());
    }
    if (j.contains("domain_full")) {
        auto arr = jstr_array(j.at("domain_full"));
        rule.domain_full.insert(rule.domain_full.end(), arr.begin(), arr.end());
    }
    if (j.contains("domainRegex")) {
        auto arr = jstr_array(j.at("domainRegex"));
        rule.domain_regex.insert(rule.domain_regex.end(), arr.begin(), arr.end());
    }
    if (j.contains("domainRegexp")) {
        auto arr = jstr_array(j.at("domainRegexp"));
        rule.domain_regex.insert(rule.domain_regex.end(), arr.begin(), arr.end());
    }
    if (j.contains("domain_regex")) {
        auto arr = jstr_array(j.at("domain_regex"));
        rule.domain_regex.insert(rule.domain_regex.end(), arr.begin(), arr.end());
    }
    if (j.contains("domain_regexp")) {
        auto arr = jstr_array(j.at("domain_regexp"));
        rule.domain_regex.insert(rule.domain_regex.end(), arr.begin(), arr.end());
    }
    if (j.contains("geosite")) {
        auto arr = jstr_array(j.at("geosite"));
        rule.geosite.insert(rule.geosite.end(), arr.begin(), arr.end());
    }

    // IP 匹配 - 处理 xray 格式 (ip 数组可能包含 geoip:xxx)
    if (j.contains("ip") && j.at("ip").is_array()) {
        for (const auto& item : j.at("ip").as_array()) {
            std::string val = std::string(item.as_string());

            if (val.substr(0, 6) == "geoip:") {
                rule.geoip.push_back(val.substr(6));
            } else {
                rule.ip.push_back(RequireRoutingIpNetwork(val, "ip"));
            }
        }
    }
    if (j.contains("geoip")) {
        auto arr = jstr_array(j.at("geoip"));
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
        if (p->is_array()) return jstr_array(*p);
        if (p->is_string()) return split_comma(std::string(p->as_string()));
        if (p->is_int64()) return {std::to_string(p->as_int64())};
        if (p->is_uint64()) return {std::to_string(p->as_uint64())};
        return {};
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
        for (const auto& value : jstr_array(j.at("source"))) {
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
    parse_http_headers(j, cfg.headers);
    cfg.real_ip_header = jstr(j, {"realIpHeader", "real_ip_header"}, "");
    return cfg;
}

HttpUpgradeConfig HttpUpgradeConfig::FromJson(const json::object& j) {
    HttpUpgradeConfig cfg;
    cfg.path = jstr(j, "path", std::string(constants::binding::kRootPath));
    cfg.host = jstr(j, "host", "");
    parse_http_headers(j, cfg.headers);
    cfg.real_ip_header = jstr(j, {"realIpHeader", "real_ip_header"}, "");
    cfg.accept_proxy_protocol = jbool(j, {"acceptProxyProtocol"}, false);
    return cfg;
}

HttpConfig HttpConfig::FromJson(const json::object& j) {
    HttpConfig cfg;
    cfg.path = jstr(j, "path", std::string(constants::binding::kRootPath));
    cfg.host = jstr(j, "host", "");
    cfg.method = jstr(j, "method", "");
    parse_http_headers(j, cfg.headers);
    cfg.real_ip_header = jstr(j, {"realIpHeader", "real_ip_header"}, "");
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

    settings->stream_settings = StreamSettings::FromJson(j);
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
    if (const auto* extra = j.if_contains("extra");
        extra && extra->is_object()) {
        const auto& extra_obj = extra->as_object();
        parse_http_headers(extra_obj, cfg.headers);
        cfg.no_grpc_header = jbool(
            extra_obj, {"noGRPCHeader", "no_grpc_header"}, cfg.no_grpc_header);
        cfg.no_sse_header = jbool(
            extra_obj, {"noSSEHeader", "no_sse_header"}, cfg.no_sse_header);
        parse_download_settings(extra_obj);
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
    if (auto* p = j.if_contains("serverNames"); p && p->is_array()) {
        cfg.server_names = jstr_array(*p);
    }
    if (cfg.server_names.empty()) {
        if (auto* p = j.if_contains("server_names"); p && p->is_array()) {
            cfg.server_names = jstr_array(*p);
        }
    }
    cfg.private_key = jstr(j, {"privateKey", "private_key"}, "");
    if (auto* p = j.if_contains("shortIds"); p && p->is_array()) {
        cfg.short_ids = jstr_array(*p);
    }
    if (cfg.short_ids.empty()) {
        if (auto* p = j.if_contains("short_ids"); p && p->is_array()) {
            cfg.short_ids = jstr_array(*p);
        }
    }
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

StreamSettings StreamSettings::FromJson(const json::object& j) {
    StreamSettings cfg;

    cfg.network  = lower_ascii_copy(
        jstr(j, "network",  std::string(constants::protocol::kTcp)));
    cfg.security = lower_ascii_copy(
        jstr(j, "security", std::string(constants::protocol::kNone)));

    // TLS 配置
    auto parse_tls = [&](std::string_view key) {
        auto* p = j.if_contains(key);
        if (!p || !p->is_object()) return;
        const auto& t = p->as_object();
        cfg.tls.server_name    = jstr(t, "serverName", "");
        cfg.tls.allow_insecure = jbool(t, {"allowInsecure"}, false);
        // ALPN
        if (auto* ap = t.if_contains("alpn"); ap && ap->is_array()) {
            cfg.tls.alpn = jstr_array(*ap);
        }
        // 证书（服务端）
        auto* certs = t.if_contains("certificates");
        if (certs && certs->is_array() && !certs->as_array().empty()) {
            const auto& c = certs->as_array()[0];
            if (c.is_object()) {
                cfg.tls.cert_file = jstr(c.as_object(), "certificateFile", "");
                cfg.tls.key_file  = jstr(c.as_object(), "keyFile", "");
            }
        }
        if (cfg.tls.cert_file.empty())
            cfg.tls.cert_file = jstr(t, "certFile", "");
        if (cfg.tls.key_file.empty())
            cfg.tls.key_file  = jstr(t, "keyFile", "");
    };
    parse_tls("tlsSettings");

    auto parse_reality = [&](std::string_view key) {
        auto* p = j.if_contains(key);
        if (p && p->is_object()) {
            cfg.reality = RealityConfig::FromJson(p->as_object());
        }
    };
    parse_reality("realitySettings");
    parse_reality("reality_settings");
    if (cfg.tls.server_name.empty() && !cfg.reality.server_name.empty()) {
        cfg.tls.server_name = cfg.reality.server_name;
    }

    // WS 配置
    auto parse_ws = [&](std::string_view key) {
        auto* p = j.if_contains(key);
        if (p && p->is_object()) {
            cfg.ws = WsConfig::FromJson(p->as_object());
        }
    };
    parse_ws("wsSettings");
    parse_ws("websocketSettings");

    auto parse_http_upgrade = [&](std::string_view key) {
        auto* p = j.if_contains(key);
        if (p && p->is_object()) {
            cfg.http_upgrade = HttpUpgradeConfig::FromJson(p->as_object());
        }
    };
    parse_http_upgrade("httpupgradeSettings");
    parse_http_upgrade("httpUpgradeSettings");

    auto parse_http = [&](std::string_view key) {
        auto* p = j.if_contains(key);
        if (p && p->is_object()) {
            cfg.http = HttpConfig::FromJson(p->as_object());
        }
    };
    parse_http("httpSettings");
    parse_http("h2Settings");
    parse_http("http_settings");

    auto parse_grpc = [&](std::string_view key) {
        auto* p = j.if_contains(key);
        if (p && p->is_object()) {
            cfg.grpc = GrpcConfig::FromJson(p->as_object());
        }
    };
    parse_grpc("grpcSettings");
    parse_grpc("grpc_settings");

    auto parse_xhttp = [&](std::string_view key) {
        auto* p = j.if_contains(key);
        if (p && p->is_object()) {
            cfg.xhttp = XHttpConfig::FromJson(p->as_object());
        }
    };
    parse_xhttp("xhttpSettings");
    parse_xhttp("splithttpSettings");
    parse_xhttp("xhttp_settings");
    parse_xhttp("splithttp_settings");

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

std::string_view StaticUserArrayKeyForProtocol(std::string_view protocol) noexcept {
    if (protocol == constants::protocol::kAnyTLS) {
        return "users";
    }
    return "clients";
}

StaticUserConfig ParseStaticUserConfig(
    std::string_view protocol,
    const json::object& settings) {
    StaticUserConfig config;
    if (const auto* method = settings.if_contains("method");
            method && method->is_string()) {
        config.method = std::string(method->as_string());
    }
    if (protocol == constants::protocol::kVless) {
        config.vless_decryption = jstr(
            settings,
            "decryption",
            std::string(constants::protocol::kNone));
    }
    auto parse_padding_scheme = [&](std::string_view key) {
        if (!config.padding_scheme.empty()) {
            return;
        }
        const auto* padding = settings.if_contains(key);
        if (!padding) {
            return;
        }
        if (padding->is_string()) {
            config.padding_scheme = std::string(padding->as_string());
            return;
        }
        if (padding->is_array()) {
            bool first = true;
            for (const auto& item : padding->as_array()) {
                if (!item.is_string()) {
                    continue;
                }
                if (!first) {
                    config.padding_scheme.push_back('\n');
                }
                config.padding_scheme.append(std::string(item.as_string()));
                first = false;
            }
        }
    };
    parse_padding_scheme("paddingScheme");
    parse_padding_scheme("padding_scheme");

    const bool ss2022_method = config.method.rfind("2022-", 0) == 0;
    StaticUser top_level_user;
    if (protocol == constants::protocol::kShadowsocks ||
        protocol == constants::protocol::kTrojan ||
        protocol == constants::protocol::kAnyTLS) {
        if (const auto* password = settings.if_contains("password");
                password && password->is_string()) {
            top_level_user.password = std::string(password->as_string());
            if (protocol == constants::protocol::kShadowsocks) {
                config.identity_password = top_level_user.password;
            }
        }
        if (const auto* email = settings.if_contains("email");
                email && email->is_string()) {
            top_level_user.email = std::string(email->as_string());
        }
    }

    bool saw_user_array = false;
    auto parse_user_array = [&](std::string_view key) {
        if (const auto* users = settings.if_contains(key);
                users && users->is_array()) {
            saw_user_array = !users->as_array().empty();
            for (const auto& client : users->as_array()) {
                if (!client.is_object()) {
                    continue;
                }
                const auto& client_obj = client.as_object();

                StaticUser user;
                if (const auto* id = client_obj.if_contains("id");
                        id && id->is_string()) {
                    user.id = std::string(id->as_string());
                }
                if (user.id.empty()) {
                    if (const auto* uuid = client_obj.if_contains("uuid");
                            uuid && uuid->is_string()) {
                        user.id = std::string(uuid->as_string());
                    }
                }
                if (const auto* password = client_obj.if_contains("password");
                        password && password->is_string()) {
                    user.password = std::string(password->as_string());
                }
                if (const auto* email = client_obj.if_contains("email");
                        email && email->is_string()) {
                    user.email = std::string(email->as_string());
                }
                if (const auto* flow = client_obj.if_contains("flow");
                        flow && flow->is_string()) {
                    user.flow = std::string(flow->as_string());
                }
                config.clients.push_back(std::move(user));
            }
        }
    };

    const auto user_array_key = StaticUserArrayKeyForProtocol(protocol);
    parse_user_array(user_array_key);
    if (protocol == constants::protocol::kVless && user_array_key != std::string_view("users")) {
        parse_user_array("users");
    }
    if (protocol == constants::protocol::kAnyTLS && config.clients.empty()) {
        parse_user_array("clients");
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

    if (j.contains("settings") && j.at("settings").is_object()) {
        cfg.static_users = ParseStaticUserConfig(cfg.protocol, j.at("settings").as_object());
    }

    if (j.contains("streamSettings") && j.at("streamSettings").is_object()) {
        cfg.stream_settings = StreamSettings::FromJson(j.at("streamSettings").as_object());
    } else if (j.contains("stream_settings") && j.at("stream_settings").is_object()) {
        cfg.stream_settings = StreamSettings::FromJson(j.at("stream_settings").as_object());
    }

    // Xray sniffing 配置
    auto parse_sniffing = [&](std::string_view key) {
        auto* p = j.if_contains(key);
        if (!p || !p->is_object()) return;
        const auto& s = p->as_object();
        cfg.sniffing.enabled = jbool(s, {"enabled"}, true);
        if (s.contains("destOverride")) {
            cfg.sniffing.dest_override = jstr_array(s.at("destOverride"));
        } else if (s.contains("dest_override")) {
            cfg.sniffing.dest_override = jstr_array(s.at("dest_override"));
        }
        if (s.contains("domainsExcluded")) {
            cfg.sniffing.domains_excluded = jstr_array(s.at("domainsExcluded"));
        } else if (s.contains("domains_excluded")) {
            cfg.sniffing.domains_excluded = jstr_array(s.at("domains_excluded"));
        }
    };
    parse_sniffing("sniffing");

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
        if (j.contains("log") && j.at("log").is_object()) {
            cfg.log_ = LogConfig::FromJson(j.at("log").as_object());
        }

        cfg.workers_ = juint32(j, "workers", cfg.workers_);
        if (cfg.workers_ > defaults::kMaxWorkers) {
            throw std::invalid_argument(std::format(
                "workers must be between 0 and {}", defaults::kMaxWorkers));
        }

        if (j.contains("dns") && j.at("dns").is_object()) {
            cfg.dns_ = DnsConfig::FromJson(j.at("dns").as_object());
        }

        if (j.contains("limits") && j.at("limits").is_object()) {
            cfg.limits_ = LimitsConfig::FromJson(j.at("limits").as_object());
        }

        if (j.contains("timeouts") && j.at("timeouts").is_object()) {
            cfg.timeouts_ = TimeoutsConfig::FromJson(j.at("timeouts").as_object());
        }

        auto parse_panels = [&](std::string_view key) {
            if (!j.contains(key)) return;
            const auto& arr = j.at(key);
            if (!arr.is_array()) return;
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
