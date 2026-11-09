#include "infra/config.hpp"
#include "common/domain_name.hpp"
#include "common/ip_utils.hpp"
#include "common/target_address.hpp"
#include "core/constants.hpp"
#include "infra/json.hpp"
#include "proxy/anytls_padding.hpp"
#include "features/routing/dispatcher.hpp"
#include "transport/internet/http_headers.hpp"
#include "transport/internet/tls_stream.hpp"
#include "infra/log.hpp"
#include <algorithm>
#include <array>
#include <cctype>
#include <cerrno>
#include <charconv>
#include <cstdio>
#include <format>
#include <limits>
#include <memory>
#include <optional>
#include <regex>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <variant>
#include <vector>


std::optional<RoutingIpNetwork> RoutingIpNetwork::Parse(std::string_view value) {
    const auto slash = value.find('/');
    if (value.empty() ||
        (slash != std::string_view::npos &&
         value.find('/', slash + 1) != std::string_view::npos)) {
        return std::nullopt;
    }

    const auto address_text = value.substr(0, slash);
    const auto parsed = iputil::ParseLiteral(address_text);
    if (!parsed) {
        return std::nullopt;
    }
    const auto& address = *parsed;

    const uint32_t max_prefix = address.is_v4() ? 32U : 128U;
    uint32_t prefix = max_prefix;
    if (slash != std::string_view::npos) {
        const auto prefix_text = value.substr(slash + 1);
        const auto [end, error] = std::from_chars(
            prefix_text.data(), prefix_text.data() + prefix_text.size(), prefix);
        if (prefix_text.empty() || error != std::errc{} ||
            end != prefix_text.data() + prefix_text.size() || prefix > max_prefix) {
            return std::nullopt;
        }
    }

    RoutingIpNetwork result;
    result.prefix_ = static_cast<uint8_t>(prefix);
    result.is_v6_ = address.is_v6();
    if (result.is_v6_) {
        const auto bytes = address.to_v6().to_bytes();
        std::ranges::copy(bytes, result.network_.begin());
    } else {
        const auto bytes = address.to_v4().to_bytes();
        std::ranges::copy(bytes, result.network_.begin());
    }

    const size_t full_bytes = prefix / 8;
    const uint8_t remaining_bits = static_cast<uint8_t>(prefix % 8);
    const size_t address_size = result.is_v6_ ? 16U : 4U;
    if (full_bytes < address_size) {
        if (remaining_bits != 0) {
            result.network_[full_bytes] &=
                static_cast<uint8_t>(0xFFU << (8 - remaining_bits));
        }
        const size_t zero_start = full_bytes + (remaining_bits != 0 ? 1U : 0U);
        std::fill(result.network_.begin() + zero_start,
                  result.network_.begin() + address_size, uint8_t{0});
    }
    return result;
}

namespace infra {

OutboundSourceConfig OutboundSourceConfig::FromJson(const json::object& j) {
    OutboundSourceConfig cfg;

    cfg.tag = JsonStringOr(j, "tag", "");
    cfg.protocol = naming::LowerAscii(JsonStringOr(j, "protocol", ""));

    auto settings = ParseJsonObject(j, "settings");
    if (!settings) {
        throw std::invalid_argument(std::move(settings.error()));
    }
    if (*settings) {
        cfg.settings = **settings;
    }

    auto stream_settings = ParseJsonObject(
        j, "streamSettings");
    if (!stream_settings) {
        throw std::invalid_argument(std::move(stream_settings.error()));
    }
    if (*stream_settings) {
        cfg.stream_settings = StreamSettings::FromJson(
            **stream_settings, StreamEndpointRole::Outbound);
    }

    cfg.send_through = ParseOptionalOutboundBind(j, "outbound");
    cfg.passthrough = JsonBoolOr(j, "passthrough", false);

    return cfg;
}

}  // namespace infra

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
    uint16_t port = 0;
    if (!TargetAddress::ParsePort(value, port)) {
        throw std::invalid_argument(std::format(
            "routing {} value '{}' must be an integer between 1 and 65535",
            field, value));
    }
    return port;
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
    uint16_t port = 53;
    const bool valid_port = !explicit_port || TargetAddress::ParsePort(port_text, port);
    if (const auto address = iputil::ParseLiteral(host);
        valid_port && address && (!text.starts_with('[') || address->is_v6())) {
        return {*address, port};
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
    if (j.contains("credentialBan")) {
        throw std::invalid_argument(
            "limits.credentialBan is not configurable; credential failure limiting is always enabled");
    }
    if (const auto* ip_ban = OptionalJsonObject(j, "ipBan")) {
        cfg.ip_ban.enabled = JsonBoolOr(*ip_ban, "enabled", cfg.ip_ban.enabled);
        cfg.ip_ban.failure_limit =
            JsonUint32Or(*ip_ban, "failureLimit", cfg.ip_ban.failure_limit);
        cfg.ip_ban.window_seconds =
            JsonUint32Or(*ip_ban, "windowSeconds", cfg.ip_ban.window_seconds);
        cfg.ip_ban.ban_seconds =
            JsonUint32Or(*ip_ban, "banSeconds", cfg.ip_ban.ban_seconds);
        if (cfg.ip_ban.failure_limit == 0 ||
            cfg.ip_ban.window_seconds == 0 ||
            cfg.ip_ban.ban_seconds == 0) {
            throw std::invalid_argument(
                "limits.ipBan failureLimit, windowSeconds and banSeconds must be greater than zero");
        }
    }
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
            if (val.starts_with("geosite:")) {
                rule.geosite.push_back(RequireRoutingSelector(
                    val.substr(8), "geosite tag", true));
            } else if (val.starts_with("full:")) {
                rule.domain_full.push_back(RequireRoutingDomainName(
                    val.substr(5), "full"));
            } else if (val.starts_with("keyword:")) {
                rule.domain_keyword.push_back(RequireRoutingDomainKeyword(
                    val.substr(8)));
            } else if (val.starts_with("regexp:")) {
                rule.domain_regex.push_back(RequireRoutingDomainRegexp(
                    val.substr(7)));
            } else if (val.starts_with("domain:")) {
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
            if (val.starts_with("geoip:")) {
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
    settings->address = RequireField(infra::NormalizeTlsServerName(
        domain::WithoutTrailingRootDot(address_val->as_string()),
        "xhttp download address"));

    if (!j.contains("port")) {
        throw std::invalid_argument("xhttp download port is required");
    }
    const auto parsed_port = ReadJsonPort(j, "port");
    if (!parsed_port.Valid()) {
        throw std::invalid_argument(
            "xhttp download port must be an integer between 1 and 65535");
    }
    settings->port = parsed_port.value;

    if (auto bind = infra::ParseOptionalOutboundBind(j, "xhttp download")) {
        settings->send_through = std::move(*bind);
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
        if (role == StreamEndpointRole::Outbound) {
            if (!cfg.reality.public_key) {
                throw std::invalid_argument(
                    "outbound REALITY requires publicKey");
            }
        } else {
            RequireField(infra::ValidateInboundReality(cfg.reality));
        }
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

// Static clients name their credential `id` or `password` depending on the
// protocol; resolve that alias here so every source yields one credential.
[[nodiscard]] std::string StaticCredential(
    std::string_view protocol, std::string id, std::string password) {
    if (protocol == constants::protocol::kVmess) return id;
    if (protocol == constants::protocol::kTrojan ||
        protocol == constants::protocol::kShadowsocks) {
        return password;
    }
    if (protocol == constants::protocol::kAnyTLS ||
        protocol == constants::protocol::kHysteria ||
        protocol == constants::protocol::kHysteria2) {
        return password.empty() ? std::move(id) : std::move(password);
    }
    return id.empty() ? std::move(password) : std::move(id);
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

    const bool ss2022_method = config.method.starts_with("2022-");
    std::string top_level_password;
    std::string top_level_email;
    if (protocol == constants::protocol::kShadowsocks ||
        protocol == constants::protocol::kTrojan ||
        protocol == constants::protocol::kAnyTLS ||
        protocol == constants::protocol::kHysteria ||
        protocol == constants::protocol::kHysteria2) {
        top_level_password = JsonStringOr(settings, "password", "");
        if (protocol == constants::protocol::kShadowsocks) {
            config.identity_password = top_level_password;
        }
        top_level_email = JsonStringOr(settings, "email", "");
    }

    if (settings.contains("users")) {
        throw std::invalid_argument(
            "static inbound settings.users is not supported; use settings.clients");
    }

    const auto* client_values = settings.if_contains("clients");
    if (client_values && !client_values->is_array()) {
        throw std::invalid_argument("clients must be an array");
    }
    const bool saw_user_array =
        client_values && !client_values->as_array().empty();

    if (!top_level_password.empty() &&
        ((protocol == constants::protocol::kShadowsocks &&
          (!ss2022_method || !saw_user_array)) ||
         ((protocol == constants::protocol::kTrojan ||
           protocol == constants::protocol::kAnyTLS ||
           protocol == constants::protocol::kHysteria ||
           protocol == constants::protocol::kHysteria2) &&
          !saw_user_array))) {
        cfg.users.push_back(InboundUserSpec{
            .user_id = 0,
            .email = std::move(top_level_email),
            .credential = std::move(top_level_password),
            .flow = {},
            .speed_limit = 0,
            .device_limit = 0,
        });
    }

    if (client_values) {
        cfg.users.reserve(cfg.users.size() + client_values->as_array().size());
        for (const auto& client : client_values->as_array()) {
            if (!client.is_object()) {
                throw std::invalid_argument("clients entries must be objects");
            }
            const auto& client_obj = client.as_object();
            cfg.users.push_back(InboundUserSpec{
                .user_id = 0,
                .email = JsonStringOr(client_obj, "email", ""),
                .credential = StaticCredential(
                    protocol,
                    JsonStringOr(client_obj, "id", ""),
                    JsonStringOr(client_obj, "password", "")),
                .flow = naming::LowerAscii(JsonStringOr(client_obj, "flow", "")),
                .speed_limit = 0,
                .device_limit = 0,
            });
        }
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

    cfg.listen = ParseInboundListen(j, "listen", "static inbound listen", cfg.listen);

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

namespace {

// 文件不存在表示“未配置”，是否允许缺省由调用方决定；打开、读取失败与 JSON
// 损坏都属于配置损坏，在此分别记录原因后阻断加载。以 fopen 的 errno 判定缺失，
// 不做 exists() 预检，避免检查与打开之间的竞态；ferror 区分读取故障与文件结束。
struct ConfigFileAbsent {};
struct ConfigFileInvalid {};
using ConfigFileLoad = std::variant<json::value, ConfigFileAbsent, ConfigFileInvalid>;

struct FileCloser {
    void operator()(std::FILE* file) const noexcept { std::fclose(file); }
};

ConfigFileLoad LoadJsonFile(const std::filesystem::path& path) {
    const auto file_name = path.filename().string();
    const std::unique_ptr<std::FILE, FileCloser> file(std::fopen(path.c_str(), "rb"));
    if (!file) {
        const int error = errno;
        if (error == ENOENT) {
            return ConfigFileAbsent{};
        }
        Log::WriteConsole(LogLevel::ERROR, std::format(
            "Configuration read failed: file={} reason={}",
            file_name, std::generic_category().message(error)));
        return ConfigFileInvalid{};
    }

    std::string content;
    std::array<char, 16 * 1024> chunk;
    for (;;) {
        const size_t read = std::fread(chunk.data(), 1, chunk.size(), file.get());
        if (read < chunk.size() && std::ferror(file.get())) {
            const int error = errno;
            Log::WriteConsole(LogLevel::ERROR, std::format(
                "Configuration read failed: file={} reason={}",
                file_name, std::generic_category().message(error)));
            return ConfigFileInvalid{};
        }
        content.append(chunk.data(), read);
        if (read < chunk.size()) {
            break;
        }
    }

    try {
        return json::parse(content, json::KeyComparison::AsciiCaseInsensitive);
    } catch (const std::exception& e) {
        Log::WriteConsole(LogLevel::ERROR, std::format(
            "Configuration parsing failed: file={} reason={}", file_name, e.what()));
        return ConfigFileInvalid{};
    }
}

// 侧车文件缺失即未配置；存在但读取、解析或校验失败都阻断加载。
template <typename ApplyFn>
bool LoadSidecarFile(const std::filesystem::path& config_dir,
                     std::string_view file_name,
                     ApplyFn&& apply) {
    auto loaded = LoadJsonFile(config_dir / file_name);
    if (std::holds_alternative<ConfigFileAbsent>(loaded)) {
        return true;
    }
    auto* value = std::get_if<json::value>(&loaded);
    if (!value) {
        Log::WriteConsole(LogLevel::ERROR, std::format(
            "Configuration sidecar load failed: file={}", file_name));
        return false;
    }
    try {
        apply(*value);
    } catch (const std::exception& e) {
        Log::WriteConsole(LogLevel::ERROR, std::format(
            "Configuration sidecar parsing failed: file={} reason={}", file_name, e.what()));
        return false;
    }
    return true;
}

template <typename AddFn>
void LoadConfigItems(const json::value& value, AddFn&& add) {
    if (!value.is_array()) {
        throw std::invalid_argument("config list must be an array of objects");
    }
    for (const auto& item : value.as_array()) {
        if (!item.is_object()) {
            throw std::invalid_argument("config list entries must be objects");
        }
        add(item.as_object());
    }
}

void LoadInboundItems(
    std::vector<StaticInboundConfig>& inbounds,
    const json::value& value) {
    LoadConfigItems(value, [&](const json::object& item) {
        inbounds.push_back(StaticInboundConfig::FromJson(item));
    });
}

void LoadOutboundItems(
    std::vector<infra::OutboundSourceConfig>& outbounds,
    const json::value& value) {
    LoadConfigItems(value, [&](const json::object& item) {
        outbounds.push_back(infra::OutboundSourceConfig::FromJson(item));
    });
}

std::vector<std::string> GetUsedRouteRuleTags(
    const RoutingConfig& routing,
    const std::vector<std::string> RouteRuleConfig::* field) {
    std::vector<std::string> tags;
    for (const auto& rule : routing.rules) {
        for (const auto& tag : rule.*field) {
            if (std::ranges::find(tags, tag) == tags.end()) {
                tags.push_back(tag);
            }
        }
    }
    return tags;
}

}  // namespace

std::optional<Config> LoadConfig(const std::filesystem::path& path) {
    std::filesystem::path config_dir;
    json::value main_config;

    std::error_code ec;
    const bool is_dir = std::filesystem::is_directory(path, ec);
    if (ec && ec != std::errc::no_such_file_or_directory && ec != std::errc::not_a_directory) {
        Log::WriteConsole(LogLevel::ERROR, std::format(
            "Configuration path stat failed: path={} reason={}",
            path.string(), ec.message()));
        return std::nullopt;
    }

    if (is_dir) {
        config_dir = path;

        auto loaded = LoadJsonFile(path / constants::paths::kDefaultConfigFile);
        if (std::holds_alternative<ConfigFileInvalid>(loaded)) {
            Log::WriteConsole(LogLevel::ERROR, std::format(
                "Main configuration load failed: file={}",
                constants::paths::kDefaultConfigFile));
            return std::nullopt;
        }
        if (auto* loaded_config = std::get_if<json::value>(&loaded)) {
            main_config = std::move(*loaded_config);
        } else {
            main_config = json::object{};
        }
    } else {
        auto file_path = path;

        config_dir = file_path.parent_path();
        if (config_dir.empty()) {
            config_dir = ".";
        }

        auto loaded = LoadJsonFile(file_path);
        auto* loaded_config = std::get_if<json::value>(&loaded);
        if (!loaded_config) {
            // 显式指定的配置文件不存在同样是错误，不回落到默认配置。
            Log::WriteConsole(LogLevel::ERROR, std::format(
                "Main configuration load failed: file={} missing={}",
                file_path.filename().string(),
                std::holds_alternative<ConfigFileAbsent>(loaded)));
            return std::nullopt;
        }
        main_config = std::move(*loaded_config);
    }

    if (!main_config.is_object()) {
        Log::WriteConsole(LogLevel::ERROR, "Main configuration must be an object");
        return std::nullopt;
    }
    auto cfg_opt = ParseConfig(main_config.as_object());
    if (!cfg_opt) {
        return std::nullopt;
    }

    Config& cfg = *cfg_opt;
    cfg.config_dir = config_dir;
    if (!cfg.panels.empty()) {
        const auto journal_dir = std::filesystem::absolute(config_dir / "traffic-journal", ec);
        if (ec) {
            Log::WriteConsole(LogLevel::ERROR, std::format(
                "Traffic journal path resolution failed: reason={}", ec.message()));
            return std::nullopt;
        }
        for (auto& panel : cfg.panels) {
            panel.TrafficJournalDir = journal_dir;
        }
    }

    const bool sidecars_loaded =
        LoadSidecarFile(config_dir, constants::paths::kInboundFile,
            [&](const json::value& value) {
                LoadInboundItems(cfg.static_inbounds, value);
            }) &&
        LoadSidecarFile(config_dir, constants::paths::kOutboundFile,
            [&](const json::value& value) {
                LoadOutboundItems(cfg.outbounds, value);
            }) &&
        LoadSidecarFile(config_dir, constants::paths::kRouteFile,
            [&](const json::value& value) {
                if (!value.is_object() || value.as_object().contains("routing")) {
                    throw std::invalid_argument(
                        "routing sidecar must be a direct routing object");
                }
                cfg.routing = RoutingConfig::FromJson(value.as_object());
            });
    if (!sidecars_loaded) {
        return std::nullopt;
    }

    bool has_direct = false;
    bool has_blackhole = false;
    for (const auto& ob : cfg.outbounds) {
        if (ob.tag == constants::protocol::kDirect) has_direct = true;
        if (ob.tag == constants::protocol::kBlackhole) has_blackhole = true;
    }

    if (!has_direct) {
        infra::OutboundSourceConfig direct;
        direct.tag = std::string(constants::protocol::kDirect);
        direct.protocol = std::string(constants::protocol::kFreedom);
        cfg.outbounds.insert(cfg.outbounds.begin(), std::move(direct));
    }

    if (!has_blackhole) {
        infra::OutboundSourceConfig blackhole;
        blackhole.tag = std::string(constants::protocol::kBlackhole);
        blackhole.protocol = std::string(constants::protocol::kBlackhole);
        cfg.outbounds.push_back(std::move(blackhole));
    }

    return cfg;
}

ConfigSemanticValidation ValidateOutboundSelectionSemantics(
    std::span<const infra::OutboundSourceConfig> outbounds,
    std::span<const RouteRuleConfig> rules,
    std::span<const StaticInboundConfig> inbounds) {
    if (outbounds.empty()) {
        return {.error = ConfigSemanticError::NoOutbounds, .index = 0, .tag = {}};
    }

    std::unordered_set<std::string_view> tags;
    tags.reserve(outbounds.size());
    for (size_t i = 0; i < outbounds.size(); ++i) {
        const std::string_view tag = outbounds[i].tag;
        if (tag.empty()) {
            return {
                .error = ConfigSemanticError::EmptyOutboundTag,
                .index = i,
                .tag = {},
            };
        }
        if (tag.starts_with(naming::kPanelNodeTagPrefix)) {
            return {.error = ConfigSemanticError::ReservedOutboundTag, .index = i, .tag = tag};
        }
        if (!tags.insert(tag).second) {
            return {
                .error = ConfigSemanticError::DuplicateOutboundTag,
                .index = i,
                .tag = tag,
            };
        }
    }

    for (size_t i = 0; i < rules.size(); ++i) {
        const std::string_view tag = rules[i].outbound_tag;
        if (tag.empty()) {
            return {
                .error = ConfigSemanticError::EmptyRouteOutboundTag,
                .index = i,
                .tag = {},
            };
        }
        if (!tags.contains(tag)) {
            return {
                .error = ConfigSemanticError::UnknownRouteOutboundTag,
                .index = i,
                .tag = tag,
            };
        }
    }

    for (size_t i = 0; i < inbounds.size(); ++i) {
        if (!inbounds[i].outbound_tag) continue;
        const std::string_view tag = *inbounds[i].outbound_tag;
        if (tag.empty()) {
            return {
                .error = ConfigSemanticError::EmptyStaticInboundOutboundTag,
                .index = i,
                .tag = tag,
            };
        }
        if (!tags.contains(tag)) {
            return {
                .error = ConfigSemanticError::UnknownStaticInboundOutboundTag,
                .index = i,
                .tag = tag,
            };
        }
    }

    return {};
}

std::string StaticInboundSemanticValidation::Message() const {
    switch (error) {
        case StaticInboundSemanticError::None: return {};
        case StaticInboundSemanticError::InvalidPort:
            return std::format("at index {} has an invalid port", index);
        case StaticInboundSemanticError::EmptyTag:
            return std::format("at index {} has an empty tag", index);
        case StaticInboundSemanticError::ReservedTag:
            return std::format("at index {} uses reserved panel tag '{}'", index, detail);
        case StaticInboundSemanticError::DuplicateTag:
            return std::format("at index {} duplicates tag '{}' from index {}", index, detail, conflicting_index);
        case StaticInboundSemanticError::DuplicateEndpoint:
            return std::format("at index {} duplicates listen endpoint '{}' from index {}", index, detail, conflicting_index);
    }
    throw std::logic_error("unknown static inbound validation result");
}

StaticInboundSemanticValidation ValidateStaticInboundSemantics(
    std::span<const StaticInboundConfig> inbounds) {
    std::unordered_map<std::string, size_t> tags;
    tags.reserve(inbounds.size());

    for (size_t i = 0; i < inbounds.size(); ++i) {
        const auto& inbound = inbounds[i];
        if (inbound.port == 0) {
            return {
                .error = StaticInboundSemanticError::InvalidPort,
                .index = i,
                .conflicting_index = 0,
                .detail = {},
            };
        }

        auto validate_tag = [&](std::string tag) -> StaticInboundSemanticValidation {
            if (tag.empty()) {
                return {
                    .error = StaticInboundSemanticError::EmptyTag,
                    .index = i,
                    .conflicting_index = 0,
                    .detail = {},
                };
            }
            if (tag.starts_with(naming::kPanelNodeTagPrefix)) {
                return {.error = StaticInboundSemanticError::ReservedTag,
                        .index = i, .conflicting_index = 0, .detail = std::move(tag)};
            }
            if (const auto [it, inserted] = tags.emplace(std::move(tag), i); !inserted) {
                return {
                    .error = StaticInboundSemanticError::DuplicateTag,
                    .index = i,
                    .conflicting_index = it->second,
                    .detail = it->first,
                };
            }
            return {};
        };

        if (inbound.tags.empty()) {
            if (auto err = validate_tag(
                    naming::BuildProtocolPortTag(inbound.protocol, inbound.port));
                !err.Ok()) {
                return err;
            }
        } else {
            for (const auto& tag : inbound.tags) {
                if (auto err = validate_tag(tag); !err.Ok()) {
                    return err;
                }
            }
        }

        for (size_t previous = 0; previous < i; ++previous) {
            if (inbounds[previous].port == inbound.port &&
                inbounds[previous].listen.Overlaps(inbound.listen)) {
                return {
                    .error = StaticInboundSemanticError::DuplicateEndpoint,
                    .index = i,
                    .conflicting_index = previous,
                    .detail = std::to_string(inbound.port),
                };
            }
        }
    }

    return {};
}

bool ValidateConfig(const Config& config) {
    if (config.workers == 0 || config.workers > defaults::kMaxWorkers) {
        LOG_CONSOLE_ERROR("Worker count must be between 1 and {}", defaults::kMaxWorkers);
        return false;
    }

    if (config.dns.servers.empty()) {
        LOG_CONSOLE_ERROR("At least one DNS server is required");
        return false;
    }

    if (config.timeouts.handshake == 0 ||
        config.timeouts.dial == 0 ||
        config.timeouts.read == 0 ||
        config.timeouts.write == 0 ||
        config.timeouts.idle == 0 ||
        config.timeouts.uplink_only == 0 ||
        config.timeouts.downlink_only == 0 ||
        config.dns.timeout == 0) {
        LOG_CONSOLE_ERROR("Timeout values must be positive");
        return false;
    }

    if (config.dns.min_ttl > config.dns.max_ttl) {
        LOG_CONSOLE_ERROR("DNS minTTL must be less than or equal to maxTTL");
        return false;
    }

    std::unordered_set<std::string> panel_nodes;
    for (const auto& panel : config.panels) {
        if (!panel.Validate()) {
            return false;
        }
        for (const int node_id : panel.NodeIDs.Values()) {
            auto key = naming::BuildPanelNodeAccountingKey(panel.Name, node_id);
            if (!panel_nodes.insert(key).second) {
                const PanelLogContext log_context{panel.Name, panel.APIHost, node_id, panel.NodeType};
                LOG_PANEL_ERROR(log_context, "Duplicate panel node identity");
                return false;
            }
        }
    }

    const auto inbound_semantic = ValidateStaticInboundSemantics(config.static_inbounds);
    if (!inbound_semantic.Ok()) {
        LOG_CONSOLE_ERROR("Static inbound {}", inbound_semantic.Message());
        return false;
    }

    const auto semantic = ValidateOutboundSelectionSemantics(
        config.outbounds, config.routing.rules, config.static_inbounds);
    switch (semantic.error) {
        case ConfigSemanticError::None:
            break;
        case ConfigSemanticError::NoOutbounds:
            LOG_CONSOLE_ERROR("At least one outbound is required");
            return false;
        case ConfigSemanticError::EmptyOutboundTag:
            LOG_CONSOLE_ERROR("Outbound at index {} has an empty tag", semantic.index);
            return false;
        case ConfigSemanticError::ReservedOutboundTag:
            LOG_CONSOLE_ERROR("Outbound at index {} uses reserved panel tag '{}'", semantic.index, semantic.tag);
            return false;
        case ConfigSemanticError::DuplicateOutboundTag:
            LOG_CONSOLE_ERROR("Duplicate outbound tag '{}' at index {}",
                      semantic.tag, semantic.index);
            return false;
        case ConfigSemanticError::EmptyRouteOutboundTag:
            LOG_CONSOLE_ERROR("Routing rule at index {} has an empty outbound tag",
                      semantic.index);
            return false;
        case ConfigSemanticError::UnknownRouteOutboundTag:
            LOG_CONSOLE_ERROR("Routing rule at index {} references unknown outbound '{}'",
                      semantic.index, semantic.tag);
            return false;
        case ConfigSemanticError::EmptyStaticInboundOutboundTag:
            LOG_CONSOLE_ERROR("Static inbound at index {} has an empty outboundTag", semantic.index);
            return false;
        case ConfigSemanticError::UnknownStaticInboundOutboundTag:
            LOG_CONSOLE_ERROR("Static inbound at index {} references unknown outboundTag '{}'",
                      semantic.index, semantic.tag);
            return false;
    }

    return true;
}

std::vector<std::string> GetUsedGeoIPTags(const RoutingConfig& routing) {
    return GetUsedRouteRuleTags(routing, &RouteRuleConfig::geoip);
}

std::vector<std::string> GetUsedGeoSiteTags(const RoutingConfig& routing) {
    return GetUsedRouteRuleTags(routing, &RouteRuleConfig::geosite);
}


namespace {

std::shared_ptr<const TlsPemMaterial> LoadValidatedPanelTlsPem(
    std::string cert_file, std::string key_file) {
    TlsConfig tls;
    tls.cert_file = std::move(cert_file);
    tls.key_file = std::move(key_file);
    LoadTlsPemMaterial(tls);
    if (!SslContext::CreateServer(tls)) {
        throw std::invalid_argument(
            "Panel TLS certificate or private key is invalid");
    }
    return std::move(tls.pem);
}

}  // namespace

PanelNodeIds PanelNodeIds::Parse(const json::value& value) {
    if (!value.is_array()) {
        throw std::invalid_argument("Panel NodeIDs must be an array");
    }
    if (value.as_array().empty()) {
        throw std::invalid_argument("Panel NodeIDs must not be empty");
    }

    PanelNodeIds result;
    std::unordered_set<int> unique;
    result.values_.reserve(value.as_array().size());
    unique.reserve(value.as_array().size());
    for (const auto& item : value.as_array()) {
        uint64_t raw = 0;
        if (item.is_int64()) {
            const int64_t signed_value = item.as_int64();
            if (signed_value <= 0) {
                throw std::invalid_argument("Panel NodeID must be positive");
            }
            raw = static_cast<uint64_t>(signed_value);
        } else if (item.is_uint64()) {
            raw = item.as_uint64();
        } else {
            throw std::invalid_argument("Panel NodeID must be an integer");
        }
        if (raw == 0 || raw > static_cast<uint64_t>(std::numeric_limits<int>::max())) {
            throw std::invalid_argument(std::format(
                "Panel NodeID {} must be between 1 and {}",
                raw, std::numeric_limits<int>::max()));
        }
        const int node_id = static_cast<int>(raw);
        if (!unique.insert(node_id).second) {
            throw std::invalid_argument(std::format(
                "Panel NodeID {} is duplicated", node_id));
        }
        result.values_.push_back(node_id);
    }
    return result;
}

PanelNodeIds PanelNodeIds::Single(int node_id) {
    if (node_id <= 0) {
        throw std::invalid_argument("Panel NodeID must be positive");
    }
    PanelNodeIds result;
    result.values_.push_back(node_id);
    return result;
}

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
    if (has_explicit_port && !TargetAddress::ParsePort(explicit_port, port)) {
        return std::nullopt;
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
    cfg.ListenIP = ParseInboundListen(j, "listenIP", "Panel listenIP", cfg.ListenIP);
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
            cfg.TLSPem = LoadValidatedPanelTlsPem(cfg.TLSCert, cfg.TLSKey);
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
        if (!TLSPem && !TLSCert.empty()) {
            try {
                (void)LoadValidatedPanelTlsPem(TLSCert, TLSKey);
            } catch (const std::exception& e) {
                LOG_PANEL_ERROR(log_context, "Panel TLS material is invalid: {}", e.what());
                return false;
            }
        }
    }
    return true;
}

namespace infra {

bool IsValidRealityServerName(std::string_view name) noexcept {
    return !name.empty() && !iputil::ParseLiteral(name) &&
           domain::IsValidDnsHostname(name, domain::TrailingDotPolicy::Forbid);
}

tl::expected<void, std::string> ApplyRealityServerInput(
    const RealityServerInput& input, RealityConfig& out) {
    if (input.private_key) {
        if (input.private_key->empty()) {
            return tl::unexpected("REALITY privateKey must not be empty");
        }
        auto parsed = transport::internet::ParseRealityKey(*input.private_key);
        if (!parsed) {
            return tl::unexpected("REALITY privateKey is invalid");
        }
        out.private_key = *parsed;
    }

    std::vector<std::string> server_names;
    server_names.reserve(input.server_names.size());
    for (const auto& name : input.server_names) {
        // An empty entry explicitly permits a REALITY ClientHello without SNI.
        if (!name.empty() && !IsValidRealityServerName(name)) {
            return tl::unexpected(
                "REALITY serverNames contains an invalid hostname");
        }
        server_names.push_back(naming::LowerAscii(name));
    }

    std::vector<transport::internet::RealityShortId> short_ids;
    short_ids.reserve(input.short_ids.size());
    for (const auto& short_id : input.short_ids) {
        auto parsed = transport::internet::ParseRealityShortId(short_id);
        if (!parsed) {
            return tl::unexpected("REALITY shortIds contains an invalid value");
        }
        short_ids.push_back(*parsed);
    }

    std::string dest_host;
    uint16_t dest_port = 0;
    if (input.dest) {
        const auto parsed = TargetAddress::Parse(*input.dest);
        if (!parsed) {
            return tl::unexpected("REALITY dest is invalid");
        }
        dest_host = parsed->IsIP()
            ? iputil::NormalizeAddressString(*parsed->resolved_addr)
            : std::string(parsed->host);
        dest_port = parsed->port;
    }

    if (input.xver > 2) {
        return tl::unexpected("REALITY xver must be between 0 and 2");
    }
    if (input.xver != 0 && (dest_host.empty() || dest_port == 0)) {
        return tl::unexpected(
            "REALITY xver 1 and 2 require dest for PROXY protocol forwarding");
    }

    std::optional<transport::internet::RealityKey> mldsa65_seed;
    if (input.mldsa65_seed) {
        auto parsed =
            transport::internet::ParseRealityMldsa65Seed(*input.mldsa65_seed);
        if (input.mldsa65_seed->empty() || !parsed) {
            return tl::unexpected("REALITY mldsa65Seed is invalid");
        }
        mldsa65_seed = *parsed;
    }

    const auto min_client_version =
        transport::internet::ParseRealityClientVersion(input.min_client_ver);
    if (!min_client_version) {
        return tl::unexpected("REALITY minClientVer is invalid");
    }
    const auto max_client_version =
        transport::internet::ParseRealityClientVersion(input.max_client_ver);
    if (!max_client_version) {
        return tl::unexpected("REALITY maxClientVer is invalid");
    }
    if (*min_client_version && *max_client_version &&
        transport::internet::RealityClientVersionValue(**min_client_version) >
            transport::internet::RealityClientVersionValue(**max_client_version)) {
        return tl::unexpected(
            "REALITY minClientVer must not exceed maxClientVer");
    }

    out.server_names = std::move(server_names);
    out.short_ids = std::move(short_ids);
    out.dest_host = std::move(dest_host);
    out.dest_port = dest_port;
    out.xver = static_cast<uint8_t>(input.xver);
    if (mldsa65_seed) {
        out.mldsa65_seed = *mldsa65_seed;
    }
    out.min_client_version = *min_client_version;
    out.max_client_version = *max_client_version;
    out.max_time_diff = input.max_time_diff;
    return {};
}

tl::expected<void, std::string> ValidateInboundReality(
    const RealityConfig& config) {
    if (!config.private_key) {
        return tl::unexpected("inbound REALITY requires privateKey");
    }
    if (config.server_names.empty()) {
        return tl::unexpected(
            "inbound REALITY requires at least one serverName");
    }
    if (config.short_ids.empty()) {
        return tl::unexpected("inbound REALITY requires at least one shortId");
    }
    return {};
}

tl::expected<std::string, std::string> NormalizeTlsServerName(
    std::string_view value, std::string_view field) {
    if (value.empty()) {
        return std::string{};
    }
    if (!iputil::ParseLiteral(value) &&
        !domain::IsValidDnsHostname(value, domain::TrailingDotPolicy::Forbid)) {
        return tl::unexpected(std::format(
            "{} must be an IP address or DNS hostname", field));
    }
    return naming::LowerAscii(std::string(value));
}

tl::expected<std::string, std::string> NormalizeTransportPath(
    std::string_view value, std::string_view field) {
    if (value.empty()) {
        return std::string(constants::binding::kRootPath);
    }
    if (!transport::internet::IsValidHttpRequestTarget(value)) {
        return tl::unexpected(std::format(
            "{} must be a valid HTTP request target", field));
    }
    return std::string(value);
}

tl::expected<std::string, std::string> NormalizeHttpAuthority(
    std::string_view value, std::string_view field) {
    if (value.empty()) {
        return std::string{};
    }
    if (!transport::internet::IsValidHttpAuthority(value)) {
        return tl::unexpected(std::format(
            "{} must be a valid HTTP authority", field));
    }
    return naming::LowerAscii(std::string(value));
}

tl::expected<void, std::string> ValidateGrpcServiceName(
    std::string_view value, std::string_view field) {
    for (const unsigned char ch : value) {
        if (ch <= 0x20 || ch == 0x7f || ch == '#') {
            return tl::unexpected(std::format(
                "{} contains invalid characters", field));
        }
    }
    GrpcConfig probe;
    probe.service_name = std::string(value);
    if (!transport::internet::IsValidHttpRequestTarget(probe.RequestPath())) {
        return tl::unexpected(std::format(
            "{} path must be a valid HTTP request target", field));
    }
    return {};
}

tl::expected<uint8_t, std::string> ParseSniffDestOverride(
    std::span<const std::string> protocols) {
    uint8_t bits = 0;
    for (const auto& raw : protocols) {
        const std::string protocol = naming::LowerAscii(raw);
        if (protocol == "fakedns" || protocol == "fakedns+others") {
            return tl::unexpected(
                "sniffing destOverride fakedns is not supported");
        }
        const uint8_t bit = SniffConfig::DestOverrideBit(protocol);
        if (bit == 0) {
            return tl::unexpected(std::format(
                "sniffing destOverride contains unsupported value '{}'",
                protocol));
        }
        bits |= bit;
    }
    return bits;
}

tl::expected<std::string, std::string> ParseAnyTlsPaddingScheme(
    const json::value& value, std::string_view field) {
    std::string scheme;
    if (value.is_null()) {
        return scheme;
    }
    if (value.is_string()) {
        scheme = std::string(value.as_string());
    } else if (value.is_array()) {
        bool first = true;
        for (const auto& item : value.as_array()) {
            if (!item.is_string()) {
                return tl::unexpected(std::format(
                    "{} must contain only strings", field));
            }
            if (!first) {
                scheme.push_back('\n');
            }
            scheme.append(item.as_string());
            first = false;
        }
    } else {
        return tl::unexpected(std::format(
            "{} must be a string, array of strings, or null", field));
    }
    if (scheme.empty()) {
        return scheme;
    }
    // The advertised raw scheme must fit in one UpdatePaddingScheme frame.
    if (scheme.size() > anytls::kMaxFramePayload) {
        return tl::unexpected(std::format(
            "{} exceeds {} bytes", field, anytls::kMaxFramePayload));
    }
    if (!anytls::ParsePaddingScheme(scheme)) {
        return tl::unexpected(std::format("{} is invalid", field));
    }
    return scheme;
}

InboundListen ParseInboundListen(
    const json::object& object,
    std::string_view key,
    std::string_view field_label,
    InboundListen fallback) {
    const auto* value = object.if_contains(key);
    if (!value) {
        return fallback;
    }
    if (!value->is_string()) {
        throw std::invalid_argument(std::format("{} must be a string", field_label));
    }
    auto parsed = InboundListen::Parse(value->as_string());
    if (!parsed) {
        throw std::invalid_argument(std::format(
            "{} '{}' must be auto or an IP address",
            field_label, value->as_string()));
    }
    return std::move(*parsed);
}

}  // namespace infra
