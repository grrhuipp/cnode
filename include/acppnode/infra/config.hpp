#pragma once

#include "acppnode/common.hpp"
#include "acppnode/protocol/sniff_config.hpp"
#include "acppnode/transport/stream_settings.hpp"
#include <boost/json.hpp>
#include <filesystem>
#include <optional>

namespace acpp {

// ============================================================================
// 日志配置
// ============================================================================
struct LogConfig {
    std::string level = "info";              // trace/debug/info/warn/error
    std::filesystem::path log_dir = "/var/log/acppnode";
    uint16_t max_days = 15;                  // 日志保留天数（按天切割）
    
    static LogConfig FromJson(const boost::json::object& j);
};

// ============================================================================
// DNS 配置
// ============================================================================
struct DnsConfig {
    std::vector<std::string> servers = {"8.8.8.8", "1.1.1.1"};
    uint32_t timeout = defaults::kDnsTimeout;
    uint32_t cache_size = defaults::kDnsCacheSize;
    uint32_t min_ttl = defaults::kDnsMinTTL;
    uint32_t max_ttl = defaults::kDnsMaxTTL;
    
    static DnsConfig FromJson(const boost::json::object& j);
};

// ============================================================================
// 面板配置
// ============================================================================
struct PanelConfig {
    std::string name;                        // 面板名称
    std::string type = "V2Board";            // 面板类型
    std::string api_host;                    // API 地址
    std::string api_key;                     // API 密钥
    std::vector<int> node_ids;               // 节点 ID 列表
    std::string node_type = "vmess";         // 节点类型: vmess/trojan/shadowsocks
    
    // TLS 配置
    // false: 强制关闭 TLS（由外部 nginx/caddy 处理）
    // true:  程序处理 TLS，根据面板下发配置决定证书
    bool tls_enable = false;
    std::string tls_cert;                    // 证书文件路径（空则自签名）
    std::string tls_key;                     // 私钥文件路径（空则自签名）
    
    static PanelConfig FromJson(const boost::json::object& j);
};

// ============================================================================
// 资源限制配置
// ============================================================================
struct LimitsConfig {
    uint32_t max_connections = defaults::kMaxConnections;
    uint32_t max_connections_per_ip = defaults::kMaxConnectionsPerIP;
    size_t buffer_size = defaults::kBufferSize;
    
    static LimitsConfig FromJson(const boost::json::object& j);
};

// ============================================================================
// 超时配置
// ============================================================================
struct TimeoutsConfig {
    uint32_t handshake = defaults::kHandshakeTimeout;       // 握手阶段预算（idle + absolute deadline）
    uint32_t dial = defaults::kDialTimeout;                 // 拨号超时
    uint32_t read = defaults::kReadTimeout;                 // 连接读方向 deadline
    uint32_t write = defaults::kWriteTimeout;               // 连接写方向 deadline
    uint32_t idle = defaults::kIdleTimeout;                 // UDP/会话空闲超时
    uint32_t uplink_only = defaults::kUplinkOnlyTimeout;    // 下行关闭后等待上行
    uint32_t downlink_only = defaults::kDownlinkOnlyTimeout;// 上行关闭后等待下行

    [[nodiscard]] std::chrono::seconds HandshakeTimeout() const noexcept {
        return std::chrono::seconds(handshake);
    }

    [[nodiscard]] std::chrono::seconds DialTimeout() const noexcept {
        return std::chrono::seconds(dial);
    }

    [[nodiscard]] std::chrono::seconds ReadTimeout() const noexcept {
        return std::chrono::seconds(read);
    }

    [[nodiscard]] std::chrono::seconds WriteTimeout() const noexcept {
        return std::chrono::seconds(write);
    }

    [[nodiscard]] std::chrono::seconds StreamIdleTimeout() const noexcept {
        return std::chrono::seconds(idle);
    }

    [[nodiscard]] std::chrono::seconds SessionIdleTimeout() const noexcept {
        return std::chrono::seconds(idle);
    }

    [[nodiscard]] std::chrono::seconds UplinkOnlyTimeout() const noexcept {
        return std::chrono::seconds(uplink_only);
    }

    [[nodiscard]] std::chrono::seconds DownlinkOnlyTimeout() const noexcept {
        return std::chrono::seconds(downlink_only);
    }
    
    static TimeoutsConfig FromJson(const boost::json::object& j);
};

// ============================================================================
// 入站配置
// ============================================================================
struct InboundConfig {
    std::vector<std::string> tags;           // 入站标识（支持多标签，匹配任一即可）
    std::string protocol;                    // vmess/trojan/...
    std::string listen = "0.0.0.0";          // 监听地址
    uint16_t port = 0;                       // 监听端口
    boost::json::object settings;             // 协议特定配置
    StreamSettings stream_settings;          // 传输层配置（network + security）
    SniffConfig sniffing;                    // 流量嗅探配置
    std::string outbound_tag;                // 固定出站（空=交由路由决策）

    static InboundConfig FromJson(const boost::json::object& j);
};

// ============================================================================
// 路由规则配置
// ============================================================================
struct RouteRuleConfig {
    // 匹配条件（可多选）
    std::vector<std::string> domain;         // 域名匹配
    std::vector<std::string> domain_suffix;  // 域名后缀
    std::vector<std::string> domain_keyword; // 域名关键词
    std::vector<std::string> domain_full;    // 完整域名
    std::vector<std::string> geosite;        // GeoSite tag (e.g., "cn", "category-ads")
    std::vector<std::string> ip;             // IP/CIDR
    std::vector<std::string> geoip;          // GeoIP tag (e.g., "cn", "private")
    std::vector<std::string> port;           // 端口 (e.g., "80", "443", "1000-2000")
    std::vector<std::string> network;        // 网络类型 (tcp/udp)
    std::vector<std::string> inbound_tag;    // 入站标签
    std::vector<std::string> user;           // 用户 email
    std::vector<std::string> source;         // 来源 IP/CIDR
    std::vector<std::string> source_port;    // 来源端口
    std::vector<std::string> protocol;       // 嗅探协议 (http/tls/bittorrent)

    std::string outbound_tag;                // 目标出站
    
    static RouteRuleConfig FromJson(const boost::json::object& j);
};

struct RoutingConfig {
    std::string domain_strategy = "AsIs";    // AsIs/IPIfNonMatch/IPOnDemand
    std::vector<RouteRuleConfig> rules;

    static RoutingConfig FromJson(const boost::json::object& j);
};

// ============================================================================
// 出站配置
// ============================================================================
struct OutboundConfig {
    std::string tag;                         // 出站标识
    std::string protocol;                    // freedom/blackhole/vmess
    boost::json::object settings;             // 协议特定配置
    StreamSettings stream_settings;          // 传输层配置（network + security）
    std::string send_through;                // 本地绑定地址（Xray 顶级 sendThrough）

    static OutboundConfig FromJson(const boost::json::object& j);
};

// ============================================================================
// 主配置
// ============================================================================
class Config {
public:
    // 从单个文件加载（兼容旧格式）
    static std::optional<Config> LoadFromFile(const std::filesystem::path& path);
    
    // 从目录加载（新格式：inbound.json, outbound.json, route.json）
    static std::optional<Config> LoadFromDirectory(const std::filesystem::path& dir);
    
    // 从 JSON 加载配置
    static std::optional<Config> LoadFromJson(const boost::json::object& j);
    
    // Getter
    const LogConfig& GetLog() const { return log_; }
    const DnsConfig& GetDns() const { return dns_; }
    const LimitsConfig& GetLimits() const { return limits_; }
    const TimeoutsConfig& GetTimeouts() const { return timeouts_; }
    const RoutingConfig& GetRouting() const { return routing_; }
    const std::vector<PanelConfig>& GetPanels() const { return panels_; }
    const std::vector<InboundConfig>& GetInbounds() const { return inbounds_; }
    const std::vector<OutboundConfig>& GetOutbounds() const { return outbounds_; }
    
    uint32_t GetWorkers() const { return workers_; }
    
    // 配置目录路径（用于加载 geo 文件）
    const std::filesystem::path& GetConfigDir() const { return config_dir_; }
    
    // 验证配置
    bool Validate() const;
    
    // 提取路由中使用的 GeoIP/GeoSite tag
    std::vector<std::string> GetUsedGeoIPTags() const;
    std::vector<std::string> GetUsedGeoSiteTags() const;
    
private:
    LogConfig log_;
    DnsConfig dns_;
    LimitsConfig limits_;
    TimeoutsConfig timeouts_;
    RoutingConfig routing_;
    std::vector<PanelConfig> panels_;
    std::vector<InboundConfig> inbounds_;
    std::vector<OutboundConfig> outbounds_;
    uint32_t workers_ = 0;  // 0 = CPU 核心数
    std::filesystem::path config_dir_;
};

}  // namespace acpp
