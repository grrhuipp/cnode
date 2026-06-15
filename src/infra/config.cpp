#include "acppnode/infra/config.hpp"
#include "acppnode/core/naming.hpp"
#include "acppnode/infra/log.hpp"
#include <algorithm>
#include <cctype>
#include <format>
#include <stdexcept>
#include <thread>

namespace acpp {

// ============================================================================
// JSON 辅助函数
// ============================================================================

namespace {

// 从 object 中取 string，不存在则返回默认值
inline std::string jstr(const json::object& obj, std::string_view key,
                        std::string_view def = "") {
    auto* p = obj.if_contains(key);
    if (!p || !p->is_string()) return std::string(def);
    return std::string(p->as_string());
}

// 从 object 中取 bool，不存在则返回默认值
inline bool jbool(const json::object& obj, std::string_view key,
                  bool def = false) {
    auto* p = obj.if_contains(key);
    if (!p || !p->is_bool()) return def;
    return p->as_bool();
}

// 从 object 中取 int64，不存在则返回默认值
inline int64_t jint(const json::object& obj, std::string_view key,
                    int64_t def = 0) {
    auto* p = obj.if_contains(key);
    if (!p) return def;
    if (p->is_int64()) return p->as_int64();
    if (p->is_uint64()) return static_cast<int64_t>(p->as_uint64());
    return def;
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

    auto days = jint(j, "maxDays", cfg.max_days);
    cfg.max_days = static_cast<uint16_t>(days);
    return cfg;
}

// ============================================================================
// DnsConfig
// ============================================================================
DnsConfig DnsConfig::FromJson(const json::object& j) {
    DnsConfig cfg;
    if (auto* servers = j.if_contains("servers"); servers && servers->is_array()) {
        auto parsed = jstr_array(*servers);
        if (!parsed.empty()) cfg.servers = std::move(parsed);
    }
    cfg.timeout    = static_cast<uint32_t>(jint(j, "timeout",   cfg.timeout));
    cfg.cache_size = static_cast<uint32_t>(jint(j, "cacheSize", cfg.cache_size));
    cfg.min_ttl    = static_cast<uint32_t>(jint(j, "minTTL",    cfg.min_ttl));
    cfg.max_ttl    = static_cast<uint32_t>(jint(j, "maxTTL",    cfg.max_ttl));
    return cfg;
}

// ============================================================================
// LimitsConfig
// ============================================================================
LimitsConfig LimitsConfig::FromJson(const json::object& j) {
    LimitsConfig cfg;
    cfg.max_connections        = static_cast<uint32_t>(jint(j, "maxConnections",      cfg.max_connections));
    cfg.max_connections_per_ip = static_cast<uint32_t>(jint(j, "maxConnectionsPerIP", cfg.max_connections_per_ip));
    return cfg;
}

// ============================================================================
// TimeoutsConfig
// ============================================================================
TimeoutsConfig TimeoutsConfig::FromJson(const json::object& j) {
    TimeoutsConfig cfg;
    cfg.handshake     = static_cast<uint32_t>(jint(j, "handshake",     cfg.handshake));
    cfg.dial          = static_cast<uint32_t>(jint(j, "dial",          cfg.dial));
    cfg.read          = static_cast<uint32_t>(jint(j, "read",          cfg.read));
    cfg.write         = static_cast<uint32_t>(jint(j, "write",         cfg.write));
    cfg.idle          = static_cast<uint32_t>(jint(j, "connIdle",      cfg.idle));
    cfg.idle          = static_cast<uint32_t>(jint(j, "idle",          cfg.idle));
    cfg.uplink_only   = static_cast<uint32_t>(jint(j, "uplinkOnly",    cfg.uplink_only));
    cfg.downlink_only = static_cast<uint32_t>(jint(j, "downlinkOnly",  cfg.downlink_only));
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
                // 暂不支持正则，跳过
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
    if (j.contains("domainKeyword")) {
        auto arr = jstr_array(j.at("domainKeyword"));
        rule.domain_keyword.insert(rule.domain_keyword.end(), arr.begin(), arr.end());
    }
    if (j.contains("domainFull")) {
        auto arr = jstr_array(j.at("domainFull"));
        rule.domain_full.insert(rule.domain_full.end(), arr.begin(), arr.end());
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
                rule.ip.push_back(val);
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
    {
        auto vals = parse_str_or_array("port");
        rule.port.insert(rule.port.end(), vals.begin(), vals.end());
    }

    // 网络类型（支持 Xray 格式: "tcp,udp"）
    {
        auto vals = parse_str_or_array("network");
        rule.network.insert(rule.network.end(), vals.begin(), vals.end());
    }

    // 入站标签
    {
        auto vals = parse_str_or_array("inboundTag");
        rule.inbound_tag.insert(rule.inbound_tag.end(), vals.begin(), vals.end());
    }

    // 用户 email（Xray user 字段）
    {
        auto vals = parse_str_or_array("user");
        rule.user.insert(rule.user.end(), vals.begin(), vals.end());
    }

    // 来源 IP/CIDR（Xray source 字段）
    if (j.contains("source") && j.at("source").is_array()) {
        rule.source = jstr_array(j.at("source"));
    }

    // 来源端口（Xray sourcePort 字段）
    {
        auto vals = parse_str_or_array("sourcePort");
        rule.source_port.insert(rule.source_port.end(), vals.begin(), vals.end());
    }

    // 嗅探协议（Xray protocol 字段）
    {
        auto vals = parse_str_or_array("protocol");
        rule.protocol.insert(rule.protocol.end(), vals.begin(), vals.end());
    }

    // 目标出站
    if (j.contains("outboundTag")) {
        rule.outbound_tag = std::string(j.at("outboundTag").as_string());
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
    // headers 字段
    auto parse_headers = [&](std::string_view key) {
        auto* p = j.if_contains(key);
        if (p && p->is_object()) {
            for (const auto& [k, v] : p->as_object()) {
                if (v.is_string()) {
                    cfg.headers[std::string(k)] = std::string(v.as_string());
                }
            }
        }
    };
    parse_headers("headers");
    cfg.real_ip_header = jstr(j, "realIpHeader", "");
    return cfg;
}

StreamSettings StreamSettings::FromJson(const json::object& j) {
    StreamSettings cfg;

    cfg.network  = jstr(j, "network",  std::string(constants::protocol::kTcp));
    cfg.security = jstr(j, "security", std::string(constants::protocol::kNone));

    // TLS 配置
    auto parse_tls = [&](std::string_view key) {
        auto* p = j.if_contains(key);
        if (!p || !p->is_object()) return;
        const auto& t = p->as_object();
        cfg.tls.server_name    = jstr(t, "serverName", "");
        cfg.tls.allow_insecure = jbool(t, "allowInsecure", false);
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

    // WS 配置
    auto parse_ws = [&](std::string_view key) {
        auto* p = j.if_contains(key);
        if (p && p->is_object()) {
            cfg.ws = WsConfig::FromJson(p->as_object());
        }
    };
    parse_ws("wsSettings");

    cfg.RecomputeModes();
    return cfg;
}

void StreamSettings::RecomputeModes() noexcept {
    // 仅初始化/配置更新时调用，热路径不再做字符串比较
    network_mode  = (network == constants::protocol::kWs)  ? NetworkMode::Ws  : NetworkMode::Tcp;
    security_mode = (security == constants::protocol::kTls) ? SecurityMode::Tls : SecurityMode::None;

    flags = kFlagNone;
    if (network_mode == NetworkMode::Ws) {
        flags |= kFlagWs;
    }
    if (security_mode == SecurityMode::Tls) {
        flags |= kFlagTls;
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
    if (const auto* padding = settings.if_contains("paddingScheme");
            padding && padding->is_array()) {
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

    const bool ss2022_method = config.method.rfind("2022-", 0) == 0;
    StaticUser top_level_user;
    if (protocol == constants::protocol::kShadowsocks) {
        if (const auto* password = settings.if_contains("password");
                password && password->is_string()) {
            top_level_user.password = std::string(password->as_string());
            config.identity_password = top_level_user.password;
        }
        if (const auto* email = settings.if_contains("email");
                email && email->is_string()) {
            top_level_user.email = std::string(email->as_string());
        }
    }

    const auto user_array_key = StaticUserArrayKeyForProtocol(protocol);
    bool saw_user_array = false;
    if (const auto* users = settings.if_contains(user_array_key);
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
            if (const auto* password = client_obj.if_contains("password");
                    password && password->is_string()) {
                user.password = std::string(password->as_string());
            }
            if (const auto* email = client_obj.if_contains("email");
                    email && email->is_string()) {
                user.email = std::string(email->as_string());
            }
            config.clients.push_back(std::move(user));
        }
    }

    if (protocol == constants::protocol::kShadowsocks &&
        !top_level_user.password.empty() &&
        (!ss2022_method || !saw_user_array)) {
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
        cfg.listen = std::string(j.at("listen").as_string());
    }

    if (j.contains("port")) {
        cfg.port = static_cast<uint16_t>(j.at("port").as_int64());
    }

    if (j.contains("settings") && j.at("settings").is_object()) {
        cfg.static_users = ParseStaticUserConfig(cfg.protocol, j.at("settings").as_object());
    }

    if (j.contains("streamSettings") && j.at("streamSettings").is_object()) {
        cfg.stream_settings = StreamSettings::FromJson(j.at("streamSettings").as_object());
    }

    // Xray sniffing 配置
    auto parse_sniffing = [&](std::string_view key) {
        auto* p = j.if_contains(key);
        if (!p || !p->is_object()) return;
        const auto& s = p->as_object();
        cfg.sniffing.enabled = jbool(s, "enabled", true);
        if (s.contains("destOverride")) {
            cfg.sniffing.dest_override = jstr_array(s.at("destOverride"));
        }
        if (s.contains("domainsExcluded")) {
            cfg.sniffing.domains_excluded = jstr_array(s.at("domainsExcluded"));
        }
    };
    parse_sniffing("sniffing");

    cfg.routing_enabled = jbool(j, "routingEnabled", cfg.routing_enabled);

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

        cfg.workers_ = static_cast<uint32_t>(jint(j, "workers", cfg.workers_));

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
