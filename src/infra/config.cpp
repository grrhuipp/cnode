#include "infra/config.hpp"
#include "common/ip_address.hpp"
#include "common/domain_name.hpp"
#include "common/ip_utils.hpp"
#include "common/target_address.hpp"
#include "core/naming.hpp"
#include "infra/json_field.hpp"
#include "infra/inbound_field_rules.hpp"
#include "infra/proxy_protocol_config.hpp"
#include "infra/outbound_bind_config.hpp"
#include "infra/log.hpp"
#include "http2_initial_window.hpp"
#include <algorithm>
#include <cctype>
#include <charconv>
#include <format>
#include <limits>
#include <optional>
#include <regex>
#include <stdexcept>
#include <thread>
#include <utility>


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

[[nodiscard]] std::string RequireRoutingDomainName(
    std::string value,
    std::string_view kind) {
    if (!domain::IsValidDnsHostname(
            value, domain::TrailingDotPolicy::Allow)) {
        throw std::invalid_argument(std::format(
            "routing domain {} contains invalid DNS hostname '{}'",
            kind, value));
    }
    domain::NormalizeDnsHostnameInPlace(value);
    if (iputil::ParseLiteral(value).has_value()) {
        throw std::invalid_argument(std::format(
            "routing domain {} contains invalid DNS hostname '{}'",
            kind, value));
    }
    return value;
}

[[nodiscard]] std::string RequireRoutingDomainKeyword(std::string value) {
    if (value.empty()) {
        throw std::invalid_argument(
            "routing domain keyword must not be empty");
    }
    for (char& ch : value) {
        const unsigned char byte = static_cast<unsigned char>(ch);
        if (byte < 0x20 || byte == 0x7f) {
            throw std::invalid_argument(
                "routing domain keyword contains control characters");
        }
        ch = domain::ToLowerAscii(byte);
    }
    return value;
}

[[nodiscard]] std::string RequireRoutingDomainRegexp(std::string value) {
    if (value.empty()) {
        throw std::invalid_argument(
            "routing domain regexp must not be empty");
    }
    for (const unsigned char byte : value) {
        if (byte < 0x20 || byte == 0x7f) {
            throw std::invalid_argument(
                "routing domain regexp contains control characters");
        }
    }
    try {
        (void)std::regex(
            value, std::regex::ECMAScript | std::regex::icase);
    } catch (const std::regex_error& error) {
        throw std::invalid_argument(std::format(
            "routing domain regexp '{}' is invalid: {}", value, error.what()));
    }
    return value;
}

[[nodiscard]] std::string RequireRoutingSelector(
    std::string value,
    std::string_view field,
    bool lowercase) {
    if (value.empty()) {
        throw std::invalid_argument(std::format(
            "routing {} must not be empty", field));
    }
    for (char& ch : value) {
        const unsigned char byte = static_cast<unsigned char>(ch);
        if (byte < 0x20 || byte == 0x7f) {
            throw std::invalid_argument(std::format(
                "routing {} contains control characters", field));
        }
        if (lowercase) {
            ch = domain::ToLowerAscii(byte);
        }
    }
    return value;
}

[[nodiscard]] std::string RequireRoutingNetwork(std::string value) {
    value = RequireRoutingSelector(std::move(value), "network", true);
    if (value != constants::protocol::kTcp &&
        value != constants::protocol::kUdp) {
        throw std::invalid_argument(std::format(
            "routing network contains unsupported value '{}'", value));
    }
    return value;
}

[[nodiscard]] routing::DomainStrategy RequireRoutingDomainStrategy(
    std::string value) {
    const std::string original = value;
    value = RequireRoutingSelector(
        std::move(value), "domainStrategy", true);
    if (value == "asis") {
        return routing::DomainStrategy::AsIs;
    }
    if (value == "ipifnonmatch") {
        return routing::DomainStrategy::IPIfNonMatch;
    }
    if (value == "ipondemand") {
        return routing::DomainStrategy::IPOnDemand;
    }
    throw std::invalid_argument(std::format(
        "routing domainStrategy contains unsupported value '{}'", original));
}

[[nodiscard]] routing::DomainStrategy ParseRoutingDomainStrategy(
    const json::object& object) {
    const auto* value = object.if_contains("domainStrategy");
    if (!value) {
        return routing::DomainStrategy::AsIs;
    }
    if (!value->is_string()) {
        throw std::invalid_argument("domainStrategy must be a string");
    }
    return RequireRoutingDomainStrategy(std::string(value->as_string()));
}

uint32_t JsonUint32Or(
    const json::object& obj,
    std::string_view key,
    uint32_t fallback) {
    auto parsed = ParseJsonUint64(
        obj, key, std::numeric_limits<uint32_t>::max());
    if (!parsed) {
        throw std::invalid_argument(std::move(parsed.error()));
    }
    return static_cast<uint32_t>(parsed->value_or(fallback));
}

const json::object* OptionalJsonObject(
    const json::object& obj,
    std::string_view key) {
    auto parsed = ParseJsonObject(obj, key);
    if (!parsed) {
        throw std::invalid_argument(std::move(parsed.error()));
    }
    return *parsed;
}

uint16_t RequiredJsonPort(const json::object& obj, std::string_view key) {
    const auto result = ReadJsonPort(obj, key);
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

std::vector<std::string> JsonStringArrayOrEmpty(
    const json::object& obj,
    std::string_view key) {
    auto parsed = ParseJsonStringArray(obj, key);
    if (!parsed) {
        throw std::invalid_argument(std::move(parsed.error()));
    }
    if (!*parsed) {
        return {};
    }
    return std::move(**parsed);
}

TlsVersion ParseTlsVersion(
    std::string_view value, std::string_view field) {
    if (value == "1.2") return TlsVersion::V1_2;
    if (value == "1.3") return TlsVersion::V1_3;
    throw std::invalid_argument(std::format(
        "tls {} must be 1.2 or 1.3", field));
}

template <typename T>
T RequireField(tl::expected<T, std::string> result) {
    if (!result) {
        throw std::invalid_argument(std::move(result.error()));
    }
    return std::move(*result);
}

void RequireField(tl::expected<void, std::string> result) {
    if (!result) {
        throw std::invalid_argument(std::move(result.error()));
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
        const std::string normalized =
            transport::internet::NormalizeHttpHeaderName(name);
        if (!transport::internet::IsValidHttpHeaderValue(raw_value.as_string())) {
            throw std::invalid_argument(std::format(
                "HTTP header '{}' contains invalid control characters",
                normalized));
        }
        std::string value(raw_value.as_string());
        if (normalized == "host") {
            value = RequireField(infra::NormalizeHttpAuthority(
                value, "HTTP header 'host'"));
        }
        const auto [existing, inserted] = headers.emplace(normalized, value);
        if (!inserted && existing->second != value) {
            throw std::invalid_argument(std::format(
                "HTTP header '{}' has conflicting values", normalized));
        }
    }
}

std::string_view TrimRoutingListItem(std::string_view value) noexcept {
    return transport::internet::TrimHttpOws(value);
}

uint16_t ParseRoutingPortNumber(std::string_view value,
                                std::string_view field) {
    value = TrimRoutingListItem(value);
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

// Xray 逗号列表的唯一拆分：逐项去除首尾空白，保留空项交由字段校验拒绝。
std::vector<std::string_view> SplitRoutingList(std::string_view text) {
    std::vector<std::string_view> items;
    size_t start = 0;
    for (;;) {
        const size_t comma = text.find(',', start);
        const size_t end = comma == std::string_view::npos ? text.size() : comma;
        items.push_back(TrimRoutingListItem(text.substr(start, end - start)));
        if (comma == std::string_view::npos) {
            return items;
        }
        start = comma + 1;
    }
}

void AppendRoutingPortText(std::vector<RoutingPortRange>& out,
                           std::string_view text,
                           std::string_view field) {
    for (const std::string_view item : SplitRoutingList(text)) {
        out.push_back(ParseRoutingPortRange(item, field));
    }
}

void AppendRoutingPortValue(std::vector<RoutingPortRange>& out,
                            const json::value& value,
                            std::string_view field) {
    if (value.is_string()) {
        AppendRoutingPortText(out, value.as_string(), field);
        return;
    }
    if (value.is_int64() || value.is_uint64()) {
        const auto parsed = JsonUnsignedInteger(value);
        if (!parsed || *parsed == 0 ||
            *parsed > std::numeric_limits<uint16_t>::max()) {
            throw std::invalid_argument(std::format(
                "routing {} must be an integer between 1 and 65535", field));
        }
        const auto port = static_cast<uint16_t>(*parsed);
        out.push_back(RoutingPortRange{.start = port, .end = port});
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
        if (value->as_array().empty()) {
            throw std::invalid_argument(std::format(
                "routing {} must not be empty", key));
        }
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
    cfg.level = naming::LowerAscii(JsonStringOr(j, "loglevel", cfg.level));
    if (!ParseLogLevel(cfg.level)) {
        throw std::invalid_argument(std::format(
            "loglevel '{}' must be none, trace, debug, info, warning, warn, or error",
            cfg.level));
    }

    const auto path_field = [&](std::string_view name, std::filesystem::path& target) {
        if (!j.contains(name)) return;
        auto value = JsonStringOr(j, name, "");
        if (value.empty()) {
            throw std::invalid_argument(std::format("{} must not be empty", name));
        }
        target = std::move(value);
    };
    path_field("logDir", cfg.log_dir);
    path_field("access", cfg.access_path);
    path_field("error", cfg.error_path);

    auto days = ParseJsonUint64(
        j, "maxDays", std::numeric_limits<uint16_t>::max());
    if (!days) {
        throw std::invalid_argument(std::move(days.error()));
    }
    cfg.max_days = static_cast<uint16_t>(days->value_or(cfg.max_days));

    cfg.rotate_daily = JsonBoolOr(j, "rotateDaily", cfg.rotate_daily);
    cfg.gzip = JsonBoolOr(j, "gzip", cfg.gzip);

    if (Log::ResolveTargetPath(cfg.log_dir, cfg.error_path, "error", cfg.rotate_daily) ==
        Log::ResolveTargetPath(cfg.log_dir, cfg.access_path, "access", cfg.rotate_daily)) {
        throw std::invalid_argument("log access and error paths must be distinct");
    }
    return cfg;
}

// ============================================================================
// DnsConfig
// ============================================================================
namespace {

udp::endpoint ParseDnsServer(std::string_view text) {
    // Endpoint syntax and default ports belong to configuration normalization.
    std::string_view host = text;
    std::string_view port_text;
    bool explicit_port = false;
    if (text.starts_with('[')) {
        host = {};
        const auto end = text.find(']');
        if (end != std::string_view::npos && text.substr(end + 1).starts_with(':')) {
            host = text.substr(1, end - 1);
            port_text = text.substr(end + 2);
            explicit_port = true;
        }
    } else if (const auto colon = text.find(':'); colon != std::string_view::npos &&
               text.find(':', colon + 1) == std::string_view::npos) {
        host = text.substr(0, colon);
        port_text = text.substr(colon + 1);
        explicit_port = true;
    }
    uint32_t port = 53;
    bool valid_port = !explicit_port;
    if (explicit_port && !port_text.empty()) {
        const auto [end, parsed] = std::from_chars(port_text.data(), port_text.data() + port_text.size(), port);
        valid_port = parsed == std::errc{} && end == port_text.data() + port_text.size() &&
            port > 0 && port <= std::numeric_limits<uint16_t>::max();
    }
    if (const auto address = iputil::ParseLiteral(host);
        valid_port && address && (!text.starts_with('[') || address->is_v6())) {
        return {*address, static_cast<uint16_t>(port)};
    }
    throw std::invalid_argument(std::format(
        "dns server '{}' must be an IP, IPv4:port or [IPv6]:port with port 1..65535", text));
}

}  // namespace

DnsConfig DnsConfig::FromJson(const json::object& j) {
    DnsConfig cfg;
    if (const auto* servers = j.if_contains("servers")) {
        if (!servers->is_array()) {
            throw std::invalid_argument("dns servers must be an array of IP endpoint strings");
        }
        cfg.servers.clear();
        cfg.servers.reserve(servers->as_array().size());
        for (const auto& server : servers->as_array()) {
            if (!server.is_string()) {
                throw std::invalid_argument("dns server must be an IP endpoint string");
            }
            cfg.servers.push_back(ParseDnsServer(server.as_string()));
        }
    }
    cfg.timeout    = JsonUint32Or(j, "timeout", cfg.timeout);
    cfg.cache_size = JsonUint32Or(j, "cacheSize", cfg.cache_size);
    cfg.min_ttl    = JsonUint32Or(j, "minTTL", cfg.min_ttl);
    cfg.max_ttl    = JsonUint32Or(j, "maxTTL", cfg.max_ttl);
    return cfg;
}

// ============================================================================
// LimitsConfig
// ============================================================================
LimitsConfig LimitsConfig::FromJson(const json::object& j) {
    LimitsConfig cfg;
    cfg.max_connections = JsonUint32Or(j, "maxConnections", cfg.max_connections);
    cfg.max_connections_per_ip = JsonUint32Or(j, "maxConnectionsPerIP", cfg.max_connections_per_ip);
    return cfg;
}

// ============================================================================
// TimeoutsConfig
// ============================================================================
TimeoutsConfig TimeoutsConfig::FromJson(const json::object& j) {
    TimeoutsConfig cfg;
    cfg.handshake = JsonUint32Or(j, "handshake", cfg.handshake);
    cfg.dial = JsonUint32Or(j, "dial", cfg.dial);
    cfg.read = JsonUint32Or(j, "read", cfg.read);
    cfg.write = JsonUint32Or(j, "write", cfg.write);
    cfg.idle = JsonUint32Or(j, "connIdle", cfg.idle);
    cfg.uplink_only = JsonUint32Or(j, "uplinkOnly", cfg.uplink_only);
    cfg.downlink_only = JsonUint32Or(j, "downlinkOnly", cfg.downlink_only);
    return cfg;
}

// ============================================================================
// RouteRuleConfig
// ============================================================================
RouteRuleConfig RouteRuleConfig::FromJson(const json::object& j) {
    RouteRuleConfig rule;

    // 域名匹配 - 处理 xray 格式 (domain 数组可能包含 geosite:xxx, full:xxx 等)
    if (j.contains("domain")) {
        auto arr = JsonStringArrayOrEmpty(j, "domain");
        if (arr.empty()) {
            throw std::invalid_argument("routing domain must not be empty");
        }
        for (std::string& val : arr) {
            // 解析前缀
            if (val.substr(0, 8) == "geosite:") {
                rule.geosite.push_back(RequireRoutingSelector(
                    val.substr(8), "geosite tag", true));
            } else if (val.substr(0, 5) == "full:") {
                rule.domain_full.push_back(RequireRoutingDomainName(
                    val.substr(5), "full"));
            } else if (val.substr(0, 8) == "keyword:") {
                rule.domain_keyword.push_back(RequireRoutingDomainKeyword(
                    val.substr(8)));
            } else if (val.substr(0, 7) == "regexp:") {
                rule.domain_regex.push_back(RequireRoutingDomainRegexp(
                    val.substr(7)));
            } else if (val.substr(0, 7) == "domain:") {
                rule.domain_suffix.push_back(RequireRoutingDomainName(
                    val.substr(7), "suffix"));
            } else {
                // 默认作为后缀匹配
                rule.domain_suffix.push_back(RequireRoutingDomainName(
                    std::move(val), "suffix"));
            }
        }
    }

    // 独立的域名字段
    if (j.contains("domainSuffix")) {
        auto arr = JsonStringArrayOrEmpty(j, "domainSuffix");
        if (arr.empty()) {
            throw std::invalid_argument(
                "routing domainSuffix must not be empty");
        }
        for (auto& value : arr) {
            rule.domain_suffix.push_back(RequireRoutingDomainName(
                std::move(value), "suffix"));
        }
    }
    if (j.contains("domainKeyword")) {
        auto arr = JsonStringArrayOrEmpty(j, "domainKeyword");
        if (arr.empty()) {
            throw std::invalid_argument(
                "routing domainKeyword must not be empty");
        }
        for (auto& value : arr) {
            rule.domain_keyword.push_back(RequireRoutingDomainKeyword(
                std::move(value)));
        }
    }
    if (j.contains("domainFull")) {
        auto arr = JsonStringArrayOrEmpty(j, "domainFull");
        if (arr.empty()) {
            throw std::invalid_argument(
                "routing domainFull must not be empty");
        }
        for (auto& value : arr) {
            rule.domain_full.push_back(RequireRoutingDomainName(
                std::move(value), "full"));
        }
    }
    if (j.contains("domainRegexp")) {
        throw std::invalid_argument("domainRegexp is not supported; use domainRegex");
    }
    if (j.contains("domainRegex")) {
        auto arr = JsonStringArrayOrEmpty(j, "domainRegex");
        if (arr.empty()) {
            throw std::invalid_argument(
                "routing domainRegex must not be empty");
        }
        for (auto& value : arr) {
            rule.domain_regex.push_back(RequireRoutingDomainRegexp(
                std::move(value)));
        }
    }
    if (j.contains("geosite")) {
        auto arr = JsonStringArrayOrEmpty(j, "geosite");
        if (arr.empty()) {
            throw std::invalid_argument(
                "routing geosite tag must not be empty");
        }
        for (auto& value : arr) {
            rule.geosite.push_back(RequireRoutingSelector(
                std::move(value), "geosite tag", true));
        }
    }

    // IP 匹配 - 处理 xray 格式 (ip 数组可能包含 geoip:xxx)
    if (j.contains("ip")) {
        auto arr = JsonStringArrayOrEmpty(j, "ip");
        if (arr.empty()) {
            throw std::invalid_argument("routing ip must not be empty");
        }
        for (std::string& val : arr) {
            if (val.substr(0, 6) == "geoip:") {
                rule.geoip.push_back(RequireRoutingSelector(
                    val.substr(6), "geoip tag", true));
            } else {
                rule.ip.push_back(RequireRoutingIpNetwork(val, "ip"));
            }
        }
    }
    if (j.contains("geoip")) {
        auto arr = JsonStringArrayOrEmpty(j, "geoip");
        if (arr.empty()) {
            throw std::invalid_argument(
                "routing geoip tag must not be empty");
        }
        for (auto& value : arr) {
            rule.geoip.push_back(RequireRoutingSelector(
                std::move(value), "geoip tag", true));
        }
    }

    // 辅助：解析字符串/数组字段，支持逗号分隔字符串（Xray 格式）
    auto parse_str_or_array = [&](std::string_view key) {
        const auto* value = j.if_contains(key);
        if (!value) {
            return std::vector<std::string>{};
        }
        std::vector<std::string> candidate;
        if (value->is_array()) {
            candidate = JsonStringArrayOrEmpty(j, key);
        } else if (value->is_string()) {
            for (const std::string_view item : SplitRoutingList(value->as_string())) {
                candidate.emplace_back(item);
            }
        } else {
            throw std::invalid_argument(std::format(
                "routing {} must be a string or array of strings", key));
        }
        if (candidate.empty()) {
            throw std::invalid_argument(std::format(
                "routing {} must not be empty", key));
        }
        return candidate;
    };

    // 端口（支持 Xray 格式: "53,443,1000-2000"）
    AppendRoutingPortField(j, "port", rule.port);

    // 网络类型（支持 Xray 格式: "tcp,udp"）
    {
        auto vals = parse_str_or_array("network");
        for (auto& value : vals) {
            rule.network.push_back(RequireRoutingNetwork(std::move(value)));
        }
    }

    // 入站标签
    {
        auto vals = parse_str_or_array("inboundTag");
        for (auto& value : vals) {
            rule.inbound_tag.push_back(RequireRoutingSelector(
                std::move(value), "inboundTag", false));
        }
    }

    // 用户 email（Xray user 字段）
    {
        auto vals = parse_str_or_array("user");
        for (auto& value : vals) {
            rule.user.push_back(RequireRoutingSelector(
                std::move(value), "user", false));
        }
    }

    // 来源 IP/CIDR（Xray source 字段）
    for (const auto& value : parse_str_or_array("source")) {
        rule.source.push_back(RequireRoutingIpNetwork(value, "source"));
    }

    // 来源端口（Xray sourcePort 字段）
    AppendRoutingPortField(j, "sourcePort", rule.source_port);

    // 嗅探协议（Xray protocol 字段）
    {
        auto vals = parse_str_or_array("protocol");
        for (auto& value : vals) {
            rule.protocol.push_back(RequireRoutingSelector(
                std::move(value), "protocol", true));
        }
    }

    // 目标出站
    rule.outbound_tag = JsonStringOr(j, "outboundTag", "");

    const bool has_condition =
        !rule.domain_suffix.empty() ||
        !rule.domain_keyword.empty() || !rule.domain_full.empty() ||
        !rule.domain_regex.empty() || !rule.geosite.empty() ||
        !rule.ip.empty() || !rule.geoip.empty() || !rule.port.empty() ||
        !rule.network.empty() || !rule.inbound_tag.empty() ||
        !rule.user.empty() || !rule.source.empty() ||
        !rule.source_port.empty() || !rule.protocol.empty();
    if (!has_condition) {
        throw std::invalid_argument(
            "routing rule must contain at least one condition");
    }

    return rule;
}

// ============================================================================
// RoutingConfig
// ============================================================================
RoutingConfig RoutingConfig::FromJson(const json::object& j) {
    RoutingConfig cfg;
    cfg.domain_strategy = ParseRoutingDomainStrategy(j);
    if (const auto* rules = j.if_contains("rules")) {
        if (!rules->is_array()) {
            throw std::invalid_argument("routing rules must be an array of objects");
        }
        for (const auto& rule : rules->as_array()) {
            if (!rule.is_object()) {
                throw std::invalid_argument("routing rules entries must be objects");
            }
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
    cfg.path = RequireField(infra::NormalizeTransportPath(
        JsonStringOr(j, "path", ""), "ws path"));
    parse_http_headers(j, cfg.headers);
    cfg.real_ip_header = naming::LowerAscii(
        JsonStringOr(j, "realIpHeader", cfg.real_ip_header));
    require_http_header_name(cfg.real_ip_header, "ws realIpHeader");
    return cfg;
}

HttpUpgradeConfig HttpUpgradeConfig::FromJson(const json::object& j) {
    HttpUpgradeConfig cfg;
    cfg.path = RequireField(infra::NormalizeTransportPath(
        JsonStringOr(j, "path", ""), "http upgrade path"));
    cfg.host = RequireField(infra::NormalizeHttpAuthority(
        JsonStringOr(j, "host", ""), "http upgrade host"));
    parse_http_headers(j, cfg.headers);
    cfg.real_ip_header = naming::LowerAscii(JsonStringOr(j, "realIpHeader", ""));
    require_http_header_name(
        cfg.real_ip_header, "http upgrade realIpHeader");
    return cfg;
}

HttpConfig HttpConfig::FromJson(const json::object& j) {
    HttpConfig cfg;
    cfg.path = RequireField(infra::NormalizeTransportPath(
        JsonStringOr(j, "path", ""), "http path"));
    cfg.host = RequireField(infra::NormalizeHttpAuthority(
        JsonStringOr(j, "host", ""), "http host"));
    cfg.method = JsonStringOr(j, "method", "");
    if (!cfg.method.empty() &&
        !transport::internet::IsValidHttpHeaderName(cfg.method)) {
        throw std::invalid_argument("http method must be a valid HTTP token");
    }
    parse_http_headers(j, cfg.headers);
    cfg.real_ip_header = naming::LowerAscii(JsonStringOr(j, "realIpHeader", ""));
    require_http_header_name(cfg.real_ip_header, "http realIpHeader");
    cfg.force_http2 = JsonBoolOr(j, "forceHttp2", false);
    auto initial_window = ParseHttp2InitialWindow(j);
    if (!initial_window) {
        throw std::invalid_argument(std::move(initial_window.error()));
    }
    cfg.initial_window_size = *initial_window;
    return cfg;
}

GrpcConfig GrpcConfig::FromJson(const json::object& j) {
    GrpcConfig cfg;
    cfg.authority = RequireField(infra::NormalizeHttpAuthority(
        JsonStringOr(j, "authority", ""), "grpc authority"));
    cfg.service_name = JsonStringOr(j, "serviceName", "");
    cfg.user_agent = JsonStringOr(j, "userAgent", "");
    cfg.multi_mode = JsonBoolOr(j, "multiMode", false);
    RequireField(infra::ValidateGrpcServiceName(
        cfg.service_name, "grpc serviceName"));
    if (!transport::internet::IsValidHttpHeaderValue(cfg.user_agent)) {
        throw std::invalid_argument(
            "grpc userAgent contains invalid control characters");
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

    const auto* address_val = j.if_contains("address");
    if (!address_val) {
        throw std::invalid_argument("xhttp download address is required");
    }
    if (!address_val->is_string() || address_val->as_string().empty()) {
        throw std::invalid_argument("xhttp download address must be a non-empty string");
    }
    std::string address(address_val->as_string());
    if (!iputil::ParseLiteral(address)) {
        if (!domain::IsValidDnsHostname(
                address, domain::TrailingDotPolicy::Allow)) {
            throw std::invalid_argument(
                "xhttp download address must be an IP literal or DNS hostname");
        }
        domain::NormalizeDnsHostnameInPlace(address);
        if (iputil::ParseLiteral(address).has_value()) {
            throw std::invalid_argument(
                "xhttp download address must be an IP literal or DNS hostname");
        }
    }
    settings->address = std::move(address);

    if (!j.contains("port")) {
        throw std::invalid_argument("xhttp download port is required");
    }
    const auto parsed_port = ReadJsonPort(j, "port");
    if (!parsed_port.Valid()) {
        throw std::invalid_argument(
            "xhttp download port must be an integer between 1 and 65535");
    }
    settings->port = parsed_port.value;

    if (j.contains("send_through") || j.contains("send_through_strategy")) {
        throw std::invalid_argument("xhttp download binding must use sendThrough/sendThroughStrategy");
    }
    const auto* send_through = j.if_contains("sendThrough");
    const auto* strategy = j.if_contains("sendThroughStrategy");
    if (strategy && !send_through) {
        throw std::invalid_argument(
            "xhttp download sendThroughStrategy requires sendThrough");
    }
    if (send_through) {
        settings->send_through = infra::ParseOutboundBindConfig(
            *send_through, strategy);
    }

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
    return settings;
}

// Xray-core SplitHTTPConfig.Build rejects any mode outside this set.
XHttpMode ParseXHttpMode(std::string_view value) {
    const std::string mode = naming::LowerAscii(std::string(value));
    if (mode.empty() || mode == "auto") return XHttpMode::Auto;
    if (mode == "packet-up") return XHttpMode::PacketUp;
    if (mode == "stream-up") return XHttpMode::StreamUp;
    if (mode == "stream-one") return XHttpMode::StreamOne;
    throw std::invalid_argument(std::format("xhttp mode '{}' is not supported", mode));
}

XHttpConfig XHttpConfig::FromJson(const json::object& j) {
    XHttpConfig cfg;
    cfg.path = RequireField(infra::NormalizeTransportPath(
        JsonStringOr(j, "path", ""), "xhttp path"));
    cfg.host = RequireField(infra::NormalizeHttpAuthority(
        JsonStringOr(j, "host", ""), "xhttp host"));
    cfg.mode = ParseXHttpMode(JsonStringOr(j, "mode", ""));
    parse_http_headers(j, cfg.headers);
    cfg.no_grpc_header = JsonBoolOr(j, "noGRPCHeader", false);
    cfg.no_sse_header = JsonBoolOr(j, "noSSEHeader", false);
    auto parse_download_settings = [&](const json::object& source) {
        const auto* declaration = source.if_contains("downloadSettings");
        if (!declaration) return;
        if (!declaration->is_object()) {
            throw std::invalid_argument("xhttp downloadSettings must be an object");
        }
        if (cfg.download_settings) {
            throw std::invalid_argument(
                "xhttp downloadSettings must be declared only once");
        }
        cfg.download_settings =
            ParseXHttpDownloadSettings(declaration->as_object());
    };
    parse_download_settings(j);
    if (const auto* extra = OptionalJsonObject(j, "extra")) {
        parse_http_headers(*extra, cfg.headers);
        cfg.no_grpc_header = JsonBoolOr(*extra, "noGRPCHeader", cfg.no_grpc_header);
        cfg.no_sse_header = JsonBoolOr(*extra, "noSSEHeader", cfg.no_sse_header);
        parse_download_settings(*extra);
    }
    if (cfg.download_settings && cfg.IsStreamOne()) {
        throw std::invalid_argument(
            "xhttp upload mode stream-one cannot use downloadSettings");
    }
    return cfg;
}

RealityConfig RealityConfig::FromJson(const json::object& j) {
    RealityConfig cfg;
    if (j.contains("show") || j.contains("type") ||
        j.contains("masterKeyLog") || j.contains("master_key_log")) {
        throw std::invalid_argument(
            "REALITY show, type, and masterKeyLog are not supported");
    }
    if (j.contains("target")) {
        throw std::invalid_argument(
            "REALITY target is not supported; use dest");
    }
    infra::RealityServerInput server;
    if (j.contains("dest")) {
        server.dest = JsonStringOr(j, "dest", "");
    }
    auto xver = ParseJsonUint64(j, "xver");
    if (!xver) {
        throw std::invalid_argument(std::move(xver.error()));
    }
    server.xver = xver->value_or(0);
    server.server_names = JsonStringArrayOrEmpty(j, "serverNames");
    if (j.contains("privateKey")) {
        server.private_key = JsonStringOr(j, "privateKey", "");
    }
    server.short_ids = JsonStringArrayOrEmpty(j, "shortIds");
    server.min_client_ver = JsonStringOr(j, "minClientVer", "");
    server.max_client_ver = JsonStringOr(j, "maxClientVer", "");
    auto max_time_diff = ParseJsonUint64(j, "maxTimeDiff");
    if (!max_time_diff) {
        throw std::invalid_argument(std::move(max_time_diff.error()));
    }
    server.max_time_diff = max_time_diff->value_or(0);
    if (j.contains("mldsa65_seed") || j.contains("mldsa65_verify")) {
        throw std::invalid_argument(
            "REALITY mldsa65_seed/mldsa65_verify is not supported; use "
            "mldsa65Seed/mldsa65Verify");
    }
    if (j.contains("mldsa65Seed")) {
        server.mldsa65_seed = JsonStringOr(j, "mldsa65Seed", "");
    }
    if (auto applied = infra::ApplyRealityServerInput(server, cfg); !applied) {
        throw std::invalid_argument(std::move(applied.error()));
    }
    const std::string mldsa65_verify = JsonStringOr(j, "mldsa65Verify", "");
    if (!mldsa65_verify.empty()) {
        auto parsed =
            transport::internet::ParseRealityMldsa65PublicKey(mldsa65_verify);
        if (!parsed) {
            throw std::invalid_argument("REALITY mldsa65Verify is invalid");
        }
        cfg.mldsa65_verify =
            std::make_shared<const transport::internet::RealityMldsa65PublicKey>(
                *parsed);
    } else if (j.contains("mldsa65Verify")) {
        throw std::invalid_argument("REALITY mldsa65Verify is invalid");
    }
    const std::string fingerprint = JsonStringOr(j, "fingerprint", "");
    if (!fingerprint.empty()) {
        auto normalized =
            transport::internet::NormalizeRealityFingerprint(fingerprint);
        if (!normalized) {
            throw std::invalid_argument("REALITY fingerprint is invalid");
        }
        cfg.fingerprint = std::move(*normalized);
    } else if (j.contains("fingerprint")) {
        throw std::invalid_argument("realitySettings.fingerprint must not be empty");
    }
    cfg.server_name = naming::LowerAscii(JsonStringOr(j, "serverName", ""));
    if (j.contains("serverName") &&
        !infra::IsValidRealityServerName(cfg.server_name)) {
        throw std::invalid_argument("REALITY serverName is invalid");
    }
    const std::string public_key = JsonStringOr(j, "publicKey", "");
    if (!public_key.empty()) {
        auto parsed = transport::internet::ParseRealityKey(public_key);
        if (!parsed) {
            throw std::invalid_argument("REALITY publicKey is invalid");
        }
        cfg.public_key = *parsed;
    } else if (j.contains("publicKey")) {
        throw std::invalid_argument("realitySettings.publicKey must not be empty");
    }
    auto short_id = transport::internet::ParseRealityShortId(
        JsonStringOr(j, "shortId", ""));
    if (!short_id) {
        throw std::invalid_argument("REALITY shortId is invalid");
    }
    cfg.short_id = *short_id;
    if (j.contains("spider_x")) {
        throw std::invalid_argument(
            "REALITY spider_x is not supported; use spiderX");
    }
    cfg.spider_x = JsonStringOr(j, "spiderX", "");
    if (!cfg.spider_x.empty() &&
        (cfg.spider_x.front() != '/' ||
         !transport::internet::IsValidHttpRequestTarget(cfg.spider_x))) {
        throw std::invalid_argument(
            "REALITY spiderX must be a valid HTTP path starting with '/'");
    }
    return cfg;
}

StreamSettings StreamSettings::FromJson(
    const json::object& j, StreamEndpointRole role) {
    StreamSettings cfg;
    bool min_version_declared = false;
    bool max_version_declared = false;

    cfg.network  = naming::LowerAscii(
        JsonStringOr(j, "network", std::string(constants::protocol::kTcp)));
    cfg.security = naming::LowerAscii(
        JsonStringOr(j, "security", std::string(constants::protocol::kNone)));

    // TLS 配置
    if (const auto* tls = OptionalJsonObject(j, "tlsSettings")) {
        min_version_declared =
            tls->contains("minVersion");
        max_version_declared =
            tls->contains("maxVersion");
        cfg.tls.min_version = ParseTlsVersion(
            JsonStringOr(*tls, "minVersion", "1.2"),
            "minVersion");
        cfg.tls.max_version = ParseTlsVersion(
            JsonStringOr(*tls, "maxVersion", "1.3"),
            "maxVersion");
        if (cfg.tls.min_version > cfg.tls.max_version) {
            throw std::invalid_argument(
                "tls minVersion must not exceed maxVersion");
        }
        cfg.tls.server_name = RequireField(infra::NormalizeTlsServerName(
            JsonStringOr(*tls, "serverName", ""), "tls serverName"));
        cfg.tls.allow_insecure = JsonBoolOr(*tls, "allowInsecure", false);
        cfg.tls.ca_file = JsonStringOr(*tls, "caFile", "");
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
        cfg.tls.alpn = JsonStringArrayOrEmpty(*tls, "alpn");
        if (!IsValidTlsAlpn(cfg.tls.alpn)) {
            throw std::invalid_argument(
                "tls alpn entries must contain between 1 and 255 bytes "
                "and must be unique");
        }
        std::optional<std::pair<std::string, std::string>> certificate_entry;
        if (const auto* certificates = tls->if_contains("certificates")) {
            if (!certificates->is_array()) {
                throw std::invalid_argument(
                    "tls certificates must be an array");
            }
            if (certificates->as_array().empty()) {
                throw std::invalid_argument(
                    "tls certificates must not be empty");
            }
            if (certificates->as_array().size() > 1) {
                throw std::invalid_argument(
                    "multiple TLS certificates are not supported");
            }
            {
                const auto& entry = certificates->as_array()[0];
                if (!entry.is_object()) {
                    throw std::invalid_argument(
                        "tls certificates entries must be objects");
                }
                std::string cert_file = JsonStringOr(entry.as_object(), "certificateFile", "");
                std::string key_file = JsonStringOr(entry.as_object(), "keyFile", "");
                if (cert_file.empty() || key_file.empty()) {
                    throw std::invalid_argument(
                        "tls certificates entry must provide certificateFile "
                        "and keyFile");
                }
                certificate_entry.emplace(
                    std::move(cert_file), std::move(key_file));
            }
        }

        std::string direct_cert_file = JsonStringOr(*tls, "certFile", "");
        std::string direct_key_file = JsonStringOr(*tls, "keyFile", "");
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
        // Workers build their contexts from these bytes; no file is opened
        // after configuration load.
        LoadTlsPemMaterial(cfg.tls);
    }

    if (const auto* reality = OptionalJsonObject(j, "realitySettings")) {
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
        if (role == StreamEndpointRole::Outbound) {
            if (!cfg.reality.public_key) {
                throw std::invalid_argument(
                    "outbound REALITY requires publicKey");
            }
        } else {
            RequireField(infra::ValidateInboundReality(cfg.reality));
        }
    }
    if (cfg.tls.server_name.empty() && !cfg.reality.server_name.empty()) {
        cfg.tls.server_name = cfg.reality.server_name;
    }

    // WS 配置
    if (j.contains("websocketSettings") ||
        j.contains("h2Settings") || j.contains("splithttpSettings")) {
        throw std::invalid_argument(
            "legacy streamSettings key alias is not supported; use wsSettings, httpupgradeSettings, httpSettings, or xhttpSettings");
    }
    if (const auto* ws = OptionalJsonObject(j, "wsSettings")) {
        cfg.ws = WsConfig::FromJson(*ws);
    }

    if (const auto* http_upgrade = OptionalJsonObject(j, "httpupgradeSettings")) {
        cfg.http_upgrade = HttpUpgradeConfig::FromJson(*http_upgrade);
    }

    if (const auto* http = OptionalJsonObject(j, "httpSettings")) {
        cfg.http = HttpConfig::FromJson(*http);
    }

    if (const auto* grpc = OptionalJsonObject(j, "grpcSettings")) {
        cfg.grpc = GrpcConfig::FromJson(*grpc);
    }

    if (const auto* xhttp = OptionalJsonObject(j, "xhttpSettings")) {
        cfg.xhttp = XHttpConfig::FromJson(*xhttp);
    }

    return NormalizeStreamSettings(cfg);
}

// ============================================================================
// StaticInboundConfig
// ============================================================================
namespace {

struct StaticClient {
    std::string id;
    std::string password;
    std::string email;
    std::string flow;
};

// Static clients name their credential `id` or `password` depending on the
// protocol; resolve that alias here so every source yields one credential.
[[nodiscard]] std::string StaticCredential(std::string_view protocol, StaticClient& client) {
    if (protocol == constants::protocol::kVmess) return std::move(client.id);
    if (protocol == constants::protocol::kTrojan ||
        protocol == constants::protocol::kShadowsocks) {
        return std::move(client.password);
    }
    if (protocol == constants::protocol::kAnyTLS ||
        protocol == constants::protocol::kHysteria ||
        protocol == constants::protocol::kHysteria2) {
        return std::move(client.password.empty() ? client.id : client.password);
    }
    return std::move(client.id.empty() ? client.password : client.id);
}

void ParseStaticSettings(
    std::string_view protocol,
    const json::object& settings,
    StaticInboundConfig& cfg) {
    auto& config = cfg.settings;
    config.method = naming::LowerAscii(JsonStringOr(settings, "method", config.method));
    if (protocol == constants::protocol::kVless) {
        config.vless_decryption = JsonStringOr(settings, "decryption", std::string(constants::protocol::kNone));
        if (transport::internet::EqualsAsciiCI(config.vless_decryption, constants::protocol::kNone)) {
            config.vless_decryption = std::string(constants::protocol::kNone);
        }
    }
    if (protocol == constants::protocol::kHysteria ||
        protocol == constants::protocol::kHysteria2) {
        config.hysteria_up_mbps =
            JsonUint32Or(settings, "upMbps", config.hysteria_up_mbps);
        config.hysteria_down_mbps =
            JsonUint32Or(settings, "downMbps", config.hysteria_down_mbps);
    }
    if (protocol == constants::protocol::kAnyTLS) {
        if (const auto* padding = settings.if_contains("paddingScheme")) {
            config.padding_scheme = RequireField(
                infra::ParseAnyTlsPaddingScheme(*padding, "paddingScheme"));
        }
    }

    const bool ss2022_method = config.method.rfind("2022-", 0) == 0;
    StaticClient top_level_user;
    if (protocol == constants::protocol::kShadowsocks ||
        protocol == constants::protocol::kTrojan ||
        protocol == constants::protocol::kAnyTLS ||
        protocol == constants::protocol::kHysteria ||
        protocol == constants::protocol::kHysteria2) {
        top_level_user.password = JsonStringOr(settings, "password", "");
        if (protocol == constants::protocol::kShadowsocks) {
            config.identity_password = top_level_user.password;
        }
        top_level_user.email = JsonStringOr(settings, "email", "");
    }

    if (settings.contains("users")) {
        throw std::invalid_argument(
            "static inbound settings.users is not supported; use settings.clients");
    }

    std::vector<StaticClient> clients;
    bool saw_user_array = false;
    if (const auto* client_values = settings.if_contains("clients")) {
        if (!client_values->is_array()) {
            throw std::invalid_argument("clients must be an array");
        }
        clients.reserve(client_values->as_array().size() + 1);
        for (const auto& client : client_values->as_array()) {
            if (!client.is_object()) {
                throw std::invalid_argument("clients entries must be objects");
            }
            const auto& client_obj = client.as_object();
            clients.push_back(StaticClient{
                .id = JsonStringOr(client_obj, "id", ""),
                .password = JsonStringOr(client_obj, "password", ""),
                .email = JsonStringOr(client_obj, "email", ""),
                .flow = naming::LowerAscii(JsonStringOr(client_obj, "flow", "")),
            });
        }
        saw_user_array = !clients.empty();
    }

    if (protocol == constants::protocol::kShadowsocks &&
        !top_level_user.password.empty() &&
        (!ss2022_method || !saw_user_array)) {
        clients.insert(clients.begin(), std::move(top_level_user));
    } else if ((protocol == constants::protocol::kTrojan ||
                protocol == constants::protocol::kAnyTLS ||
                protocol == constants::protocol::kHysteria ||
                protocol == constants::protocol::kHysteria2) &&
               !top_level_user.password.empty() &&
               !saw_user_array) {
        clients.insert(clients.begin(), std::move(top_level_user));
    }

    cfg.users.reserve(clients.size());
    for (auto& client : clients) {
        cfg.users.push_back(InboundUserSpec{
            .user_id = 0,
            .email = std::move(client.email),
            .credential = StaticCredential(protocol, client),
            .flow = std::move(client.flow),
            .speed_limit = 0,
            .device_limit = 0,
        });
    }

    // A single static SS2022 user whose PSK is the server PSK is the
    // single-user form without an identity header.
    if (protocol == constants::protocol::kShadowsocks &&
        cfg.users.size() == 1 &&
        cfg.users.front().credential == config.identity_password) {
        config.identity_password.clear();
    }
}

}  // namespace

StaticInboundConfig StaticInboundConfig::FromJson(const json::object& j) {
    StaticInboundConfig cfg;

    // tag 支持字符串或数组（多标签匹配任一）
    if (const auto* p = j.if_contains("tag")) {
        if (p->is_string()) {
            cfg.tags.push_back(std::string(p->as_string()));
        } else if (p->is_array()) {
            if (p->as_array().empty()) {
                throw std::invalid_argument("static inbound tag array must not be empty");
            }
            for (const auto& item : p->as_array()) {
                if (!item.is_string()) {
                    throw std::invalid_argument("static inbound tag array must contain only strings");
                }
                cfg.tags.push_back(std::string(item.as_string()));
            }
        } else {
            throw std::invalid_argument("static inbound tag must be a string or array of strings");
        }
    }

    if (const auto* proto = j.if_contains("protocol")) {
        if (!proto->is_string()) {
            throw std::invalid_argument("static inbound protocol must be a string");
        }
        cfg.protocol = naming::LowerAscii(std::string(proto->as_string()));
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

    cfg.port = RequiredJsonPort(j, "port");
    cfg.proxy_protocol = ParseProxyProtocolMode(j, "proxyProtocol");

    if (const auto* settings = OptionalJsonObject(j, "settings")) {
        ParseStaticSettings(cfg.protocol, *settings, cfg);
    }

    if (const auto* stream_settings = OptionalJsonObject(j, "streamSettings")) {
        cfg.stream_settings = StreamSettings::FromJson(
            *stream_settings, StreamEndpointRole::Inbound);
    }

    // Xray sniffing 配置
    if (const auto* sniffing = OptionalJsonObject(j, "sniffing")) {
        cfg.sniffing.enabled = JsonBoolOr(*sniffing, "enabled", true);
        cfg.sniffing.metadata_only = JsonBoolOr(*sniffing, "metadataOnly", false);
        cfg.sniffing.route_only = JsonBoolOr(*sniffing, "routeOnly", true);
        cfg.sniffing.domains_excluded =
            JsonStringArrayOrEmpty(*sniffing, "domainsExcluded");
        for (auto& excluded : cfg.sniffing.domains_excluded) {
            if (!domain::IsValidDnsHostname(
                    excluded, domain::TrailingDotPolicy::Allow)) {
                throw std::invalid_argument(std::format(
                    "sniffing domainsExcluded contains invalid DNS hostname '{}'",
                    excluded));
            }
            domain::NormalizeDnsHostnameInPlace(excluded);
        }
        cfg.sniffing.dest_override = RequireField(infra::ParseSniffDestOverride(
            JsonStringArrayOrEmpty(*sniffing, "destOverride")));
    }

    if (j.contains("routing_enabled")) {
        throw std::invalid_argument(
            "static inbound routing selection must use routingEnabled");
    }
    cfg.routing_enabled = JsonBoolOr(j, "routingEnabled", false);
    if (j.contains("outbound_tag") || j.contains("outbound")) {
        throw std::invalid_argument(
            "static inbound outbound selection must use outboundTag");
    }
    if (j.contains("outboundTag")) {
        cfg.outbound_tag = JsonStringOr(j, "outboundTag", "");
        if (cfg.outbound_tag->empty()) {
            throw std::invalid_argument(
                "static inbound outboundTag must not be empty");
        }
    }

    return cfg;
}

// ============================================================================
// Config
// ============================================================================

std::optional<Config> ParseConfig(const json::object& j) {
    Config cfg;

    try {
        if (const auto* log = OptionalJsonObject(j, "log")) {
            cfg.log = LogConfig::FromJson(*log);
        }

        cfg.workers = JsonUint32Or(j, "workers", cfg.workers);
        if (cfg.workers > defaults::kMaxWorkers) {
            throw std::invalid_argument(std::format(
                "workers must be between 0 and {}", defaults::kMaxWorkers));
        }

        if (const auto* dns = OptionalJsonObject(j, "dns")) {
            cfg.dns = DnsConfig::FromJson(*dns);
        }

        if (const auto* limits = OptionalJsonObject(j, "limits")) {
            cfg.limits = LimitsConfig::FromJson(*limits);
        }

        if (const auto* timeouts = OptionalJsonObject(j, "timeouts")) {
            cfg.timeouts = TimeoutsConfig::FromJson(*timeouts);
        }

        if (const auto* panels = j.if_contains("panels")) {
            if (!panels->is_array()) {
                throw std::invalid_argument("panels must be an array");
            }
            for (const auto& panel : panels->as_array()) {
                if (!panel.is_object()) {
                    throw std::invalid_argument("panel entry must be an object");
                }
                cfg.panels.push_back(PanelConfig::FromJson(panel.as_object()));
            }
        }

        // Workers 默认值
        if (cfg.workers == 0) {
            cfg.workers = std::thread::hardware_concurrency();
            if (cfg.workers == 0) {
                cfg.workers = 1;  // 至少 1 个
            }
        }

        return cfg;

    } catch (const std::exception& e) {
        Log::WriteConsole(LogLevel::ERROR, std::format("Failed to parse config: {}", e.what()));
        return std::nullopt;
    }
}

