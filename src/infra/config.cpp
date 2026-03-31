#include "acppnode/infra/config.hpp"
#include "acppnode/infra/log.hpp"
#include <thread>

namespace acpp {

// ============================================================================
// JSON 辅助函数
// ============================================================================

namespace {

// 从 object 中取 string，不存在则返回默认值
inline std::string jstr(const boost::json::object& obj, std::string_view key,
                        std::string_view def = "") {
    auto* p = obj.if_contains(key);
    if (!p || !p->is_string()) return std::string(def);
    return std::string(p->as_string());
}

// 双键版本：先查 key1（camelCase），再查 key2（PascalCase）
inline std::string jstr2(const boost::json::object& obj,
                         std::string_view key1, std::string_view key2,
                         std::string_view def = "") {
    auto* p = obj.if_contains(key1);
    if (p && p->is_string()) return std::string(p->as_string());
    auto* q = obj.if_contains(key2);
    if (q && q->is_string()) return std::string(q->as_string());
    return std::string(def);
}

// 从 object 中取 bool，不存在则返回默认值
inline bool jbool(const boost::json::object& obj, std::string_view key,
                  bool def = false) {
    auto* p = obj.if_contains(key);
    if (!p || !p->is_bool()) return def;
    return p->as_bool();
}

// 双键版本
inline bool jbool2(const boost::json::object& obj,
                   std::string_view key1, std::string_view key2,
                   bool def = false) {
    auto* p = obj.if_contains(key1);
    if (p && p->is_bool()) return p->as_bool();
    auto* q = obj.if_contains(key2);
    if (q && q->is_bool()) return q->as_bool();
    return def;
}

// 从 object 中取 int64，双键版本
inline int64_t jint2(const boost::json::object& obj,
                     std::string_view key1, std::string_view key2,
                     int64_t def = 0) {
    for (auto key : {key1, key2}) {
        auto* p = obj.if_contains(key);
        if (!p) continue;
        if (p->is_int64()) return p->as_int64();
        if (p->is_uint64()) return static_cast<int64_t>(p->as_uint64());
    }
    return def;
}

// 从 JSON array 中提取 string vector
inline std::vector<std::string> jstr_array(const boost::json::value& v) {
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

// 从 JSON array 中提取 int vector
inline std::vector<int> jint_array(const boost::json::value& v) {
    std::vector<int> result;
    if (v.is_array()) {
        for (const auto& item : v.as_array()) {
            if (item.is_int64()) {
                result.push_back(static_cast<int>(item.as_int64()));
            } else if (item.is_uint64()) {
                result.push_back(static_cast<int>(item.as_uint64()));
            }
        }
    }
    return result;
}

// 从 object 中取 string array，双键版本
inline std::vector<std::string> jstr_array2(const boost::json::object& obj,
                                            std::string_view key1, std::string_view key2) {
    auto* p = obj.if_contains(key1);
    if (p && p->is_array()) return jstr_array(*p);
    auto* q = obj.if_contains(key2);
    if (q && q->is_array()) return jstr_array(*q);
    return {};
}

// 从 object 中取 int array，双键版本
inline std::vector<int> jint_array2(const boost::json::object& obj,
                                    std::string_view key1, std::string_view key2) {
    auto* p = obj.if_contains(key1);
    if (p && p->is_array()) return jint_array(*p);
    auto* q = obj.if_contains(key2);
    if (q && q->is_array()) return jint_array(*q);
    return {};
}

} // anonymous namespace

// ============================================================================
// LogConfig
// ============================================================================
LogConfig LogConfig::FromJson(const boost::json::object& j) {
    LogConfig cfg;
    // 支持 Xray "loglevel" 和 cnode "level"/"Level"
    auto level = jstr2(j, "loglevel", "level");
    if (level.empty()) level = jstr(j, "Level");
    if (!level.empty()) cfg.level = level;

    auto dir = jstr2(j, "logDir", "LogDir");
    if (!dir.empty()) cfg.log_dir = dir;

    auto days = jint2(j, "maxDays", "MaxDays", cfg.max_days);
    cfg.max_days = static_cast<uint16_t>(days);
    return cfg;
}

// ============================================================================
// DnsConfig
// ============================================================================
DnsConfig DnsConfig::FromJson(const boost::json::object& j) {
    DnsConfig cfg;
    auto servers = jstr_array2(j, "servers", "Servers");
    if (!servers.empty()) cfg.servers = std::move(servers);
    cfg.timeout    = static_cast<uint32_t>(jint2(j, "timeout",   "Timeout",   cfg.timeout));
    cfg.cache_size = static_cast<uint32_t>(jint2(j, "cacheSize", "CacheSize", cfg.cache_size));
    cfg.min_ttl    = static_cast<uint32_t>(jint2(j, "minTTL",    "MinTTL",    cfg.min_ttl));
    cfg.max_ttl    = static_cast<uint32_t>(jint2(j, "maxTTL",    "MaxTTL",    cfg.max_ttl));
    return cfg;
}

// ============================================================================
// PanelConfig
// ============================================================================
PanelConfig PanelConfig::FromJson(const boost::json::object& j) {
    PanelConfig cfg;
    cfg.name      = jstr2(j, "name",      "Name");
    cfg.type      = jstr2(j, "type",      "Type",      std::string(constants::panel::kV2BoardType));
    cfg.api_host  = jstr2(j, "apiHost",   "ApiHost");
    cfg.api_key   = jstr2(j, "apiKey",    "ApiKey");
    cfg.node_type = jstr2(j, "nodeType",  "NodeType",  std::string(constants::panel::kDefaultNodeType));

    auto ids = jint_array2(j, "nodeID", "NodeID");
    if (!ids.empty()) cfg.node_ids = std::move(ids);

    cfg.tls_enable = jbool2(j, "tlsEnable", "TlsEnable", false);
    cfg.tls_cert   = jstr2(j, "tlsCert",    "TlsCert");
    cfg.tls_key    = jstr2(j, "tlsKey",     "TlsKey");
    return cfg;
}

// ============================================================================
// LimitsConfig
// ============================================================================
LimitsConfig LimitsConfig::FromJson(const boost::json::object& j) {
    LimitsConfig cfg;
    cfg.max_connections        = static_cast<uint32_t>(jint2(j, "maxConnections",      "MaxConnections",      cfg.max_connections));
    cfg.max_connections_per_ip = static_cast<uint32_t>(jint2(j, "maxConnectionsPerIP", "MaxConnectionsPerIP", cfg.max_connections_per_ip));
    cfg.buffer_size            = static_cast<size_t>(jint2(j, "bufferSize",            "BufferSize",          static_cast<int64_t>(cfg.buffer_size)));
    return cfg;
}

// ============================================================================
// TimeoutsConfig
// ============================================================================
TimeoutsConfig TimeoutsConfig::FromJson(const boost::json::object& j) {
    TimeoutsConfig cfg;
    cfg.handshake     = static_cast<uint32_t>(jint2(j, "handshake",     "Handshake",     cfg.handshake));
    cfg.dial          = static_cast<uint32_t>(jint2(j, "dial",          "Dial",          cfg.dial));
    cfg.read          = static_cast<uint32_t>(jint2(j, "read",          "Read",          cfg.read));
    cfg.write         = static_cast<uint32_t>(jint2(j, "write",         "Write",         cfg.write));
    cfg.idle          = static_cast<uint32_t>(jint2(j, "idle",          "Idle",          cfg.idle));
    cfg.uplink_only   = static_cast<uint32_t>(jint2(j, "uplinkOnly",   "UplinkOnly",    cfg.uplink_only));
    cfg.downlink_only = static_cast<uint32_t>(jint2(j, "downlinkOnly", "DownlinkOnly",  cfg.downlink_only));
    return cfg;
}

// ============================================================================
// RouteRuleConfig
// ============================================================================
RouteRuleConfig RouteRuleConfig::FromJson(const boost::json::object& j) {
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

    // 兼容旧格式
    if (j.contains("OutboundTag")) {
        rule.outbound_tag = std::string(j.at("OutboundTag").as_string());
    }
    // 兼容旧格式的简单规则
    if (j.contains("Type") && j.contains("Value")) {
        std::string type = std::string(j.at("Type").as_string());
        std::string value = std::string(j.at("Value").as_string());
        if (type == "domain") {
            rule.domain_suffix.push_back(value);
        } else if (type == "ip") {
            rule.ip.push_back(value);
        }
    }

    return rule;
}

// ============================================================================
// RoutingConfig
// ============================================================================
RoutingConfig RoutingConfig::FromJson(const boost::json::object& j) {
    RoutingConfig cfg;
    if (j.contains("DomainStrategy")) {
        cfg.domain_strategy = std::string(j.at("DomainStrategy").as_string());
    }
    if (j.contains("domainStrategy")) {
        cfg.domain_strategy = std::string(j.at("domainStrategy").as_string());
    }
    if (j.contains("Rules")) {
        for (const auto& rule : j.at("Rules").as_array()) {
            cfg.rules.push_back(RouteRuleConfig::FromJson(rule.as_object()));
        }
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

WsConfig WsConfig::FromJson(const boost::json::object& j) {
    WsConfig cfg;
    cfg.path = jstr(j, "path", jstr(j, "Path", std::string(constants::binding::kRootPath)));
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
    parse_headers("Headers");
    cfg.real_ip_header = jstr(j, "realIpHeader", jstr(j, "real_ip_header", ""));
    return cfg;
}

StreamSettings StreamSettings::FromJson(const boost::json::object& j) {
    StreamSettings cfg;

    // network / Network
    cfg.network  = jstr(j, "network",  jstr(j, "Network",  std::string(constants::protocol::kTcp)));
    cfg.security = jstr(j, "security", jstr(j, "Security", std::string(constants::protocol::kNone)));

    // TLS 配置（支持 tlsSettings / TlsSettings 两种 key）
    auto parse_tls = [&](std::string_view key) {
        auto* p = j.if_contains(key);
        if (!p || !p->is_object()) return;
        const auto& t = p->as_object();
        cfg.tls.server_name    = jstr(t, "serverName",    jstr(t, "ServerName",    ""));
        cfg.tls.allow_insecure = jbool(t, "allowInsecure", jbool(t, "AllowInsecure", false));
        // ALPN
        if (auto* ap = t.if_contains("alpn"); ap && ap->is_array()) {
            cfg.tls.alpn = jstr_array(*ap);
        } else if (auto* ap2 = t.if_contains("Alpn"); ap2 && ap2->is_array()) {
            cfg.tls.alpn = jstr_array(*ap2);
        }
        // 证书（服务端）
        auto* certs = t.if_contains("certificates");
        if (!certs) certs = t.if_contains("Certificates");
        if (certs && certs->is_array() && !certs->as_array().empty()) {
            const auto& c = certs->as_array()[0];
            if (c.is_object()) {
                cfg.tls.cert_file = jstr(c.as_object(), "certificateFile",
                                   jstr(c.as_object(), "CertificateFile", ""));
                cfg.tls.key_file  = jstr(c.as_object(), "keyFile",
                                   jstr(c.as_object(), "KeyFile",  ""));
            }
        }
        // 也支持直接的 cert/key 字段
        if (cfg.tls.cert_file.empty())
            cfg.tls.cert_file = jstr(t, "certFile", jstr(t, "CertFile", ""));
        if (cfg.tls.key_file.empty())
            cfg.tls.key_file  = jstr(t, "keyFile",  jstr(t, "KeyFile",  ""));
    };
    parse_tls("tlsSettings");
    parse_tls("TlsSettings");

    // WS 配置（支持 wsSettings / WsSettings 两种 key）
    auto parse_ws = [&](std::string_view key) {
        auto* p = j.if_contains(key);
        if (p && p->is_object()) {
            cfg.ws = WsConfig::FromJson(p->as_object());
        }
    };
    parse_ws("wsSettings");
    parse_ws("WsSettings");

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
// InboundConfig
// ============================================================================
InboundConfig InboundConfig::FromJson(const boost::json::object& j) {
    InboundConfig cfg;

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
    if (cfg.tags.empty()) parse_tag("Tag");

    if (j.contains("protocol")) {
        cfg.protocol = std::string(j.at("protocol").as_string());
    } else if (j.contains("Protocol")) {
        cfg.protocol = std::string(j.at("Protocol").as_string());
    }

    if (j.contains("listen")) {
        cfg.listen = std::string(j.at("listen").as_string());
    } else if (j.contains("Listen")) {
        cfg.listen = std::string(j.at("Listen").as_string());
    }

    if (j.contains("port")) {
        cfg.port = static_cast<uint16_t>(j.at("port").as_int64());
    } else if (j.contains("Port")) {
        cfg.port = static_cast<uint16_t>(j.at("Port").as_int64());
    }

    if (j.contains("settings") && j.at("settings").is_object()) {
        cfg.settings = j.at("settings").as_object();
    } else if (j.contains("Settings") && j.at("Settings").is_object()) {
        cfg.settings = j.at("Settings").as_object();
    }

    if (j.contains("streamSettings") && j.at("streamSettings").is_object()) {
        cfg.stream_settings = StreamSettings::FromJson(j.at("streamSettings").as_object());
    } else if (j.contains("StreamSettings") && j.at("StreamSettings").is_object()) {
        cfg.stream_settings = StreamSettings::FromJson(j.at("StreamSettings").as_object());
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
    parse_sniffing("Sniffing");

    if (j.contains("outbound") && j.at("outbound").is_string())
        cfg.outbound_tag = std::string(j.at("outbound").as_string());
    else if (j.contains("outboundTag") && j.at("outboundTag").is_string())
        cfg.outbound_tag = std::string(j.at("outboundTag").as_string());

    return cfg;
}

// ============================================================================
// OutboundConfig
// ============================================================================
OutboundConfig OutboundConfig::FromJson(const boost::json::object& j) {
    OutboundConfig cfg;

    // 支持大小写混合
    if (j.contains("tag")) {
        cfg.tag = std::string(j.at("tag").as_string());
    } else if (j.contains("Tag")) {
        cfg.tag = std::string(j.at("Tag").as_string());
    }

    if (j.contains("protocol")) {
        cfg.protocol = std::string(j.at("protocol").as_string());
    } else if (j.contains("Protocol")) {
        cfg.protocol = std::string(j.at("Protocol").as_string());
    }

    if (j.contains("settings") && j.at("settings").is_object()) {
        cfg.settings = j.at("settings").as_object();
    } else if (j.contains("Settings") && j.at("Settings").is_object()) {
        cfg.settings = j.at("Settings").as_object();
    }

    if (j.contains("streamSettings") && j.at("streamSettings").is_object()) {
        cfg.stream_settings = StreamSettings::FromJson(j.at("streamSettings").as_object());
    } else if (j.contains("StreamSettings") && j.at("StreamSettings").is_object()) {
        cfg.stream_settings = StreamSettings::FromJson(j.at("StreamSettings").as_object());
    }

    // Xray 顶级 sendThrough 字段
    if (j.contains("sendThrough") && j.at("sendThrough").is_string()) {
        cfg.send_through = std::string(j.at("sendThrough").as_string());
    } else if (j.contains("SendThrough") && j.at("SendThrough").is_string()) {
        cfg.send_through = std::string(j.at("SendThrough").as_string());
    }

    return cfg;
}

// ============================================================================
// Config
// ============================================================================

std::optional<Config> Config::LoadFromJson(const boost::json::object& j) {
    Config cfg;

    try {
        // Log（支持 "log" / "Log"）
        if (j.contains("log") && j.at("log").is_object()) {
            cfg.log_ = LogConfig::FromJson(j.at("log").as_object());
        } else if (j.contains("Log") && j.at("Log").is_object()) {
            cfg.log_ = LogConfig::FromJson(j.at("Log").as_object());
        }

        // Workers（支持 "workers" / "Workers"）
        cfg.workers_ = static_cast<uint32_t>(jint2(j, "workers", "Workers", cfg.workers_));

        // DNS（支持 "dns" / "Dns"）
        if (j.contains("dns") && j.at("dns").is_object()) {
            cfg.dns_ = DnsConfig::FromJson(j.at("dns").as_object());
        } else if (j.contains("Dns") && j.at("Dns").is_object()) {
            cfg.dns_ = DnsConfig::FromJson(j.at("Dns").as_object());
        }

        // Limits（支持 "limits" / "Limits"）
        if (j.contains("limits") && j.at("limits").is_object()) {
            cfg.limits_ = LimitsConfig::FromJson(j.at("limits").as_object());
        } else if (j.contains("Limits") && j.at("Limits").is_object()) {
            cfg.limits_ = LimitsConfig::FromJson(j.at("Limits").as_object());
        }

        // Timeouts（支持 "timeouts" / "Timeouts"）
        if (j.contains("timeouts") && j.at("timeouts").is_object()) {
            cfg.timeouts_ = TimeoutsConfig::FromJson(j.at("timeouts").as_object());
        } else if (j.contains("Timeouts") && j.at("Timeouts").is_object()) {
            cfg.timeouts_ = TimeoutsConfig::FromJson(j.at("Timeouts").as_object());
        }

        // Panels（支持 "panels" / "Panels"）
        auto parse_panels = [&](std::string_view key) {
            if (!j.contains(key)) return;
            const auto& arr = j.at(key);
            if (!arr.is_array()) return;
            for (const auto& panel : arr.as_array()) {
                cfg.panels_.push_back(PanelConfig::FromJson(panel.as_object()));
            }
        };
        parse_panels("panels");
        if (cfg.panels_.empty()) parse_panels("Panels");

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
