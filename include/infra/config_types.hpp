#pragma once

#include "common/asio_types.hpp"
#include "common/defaults.hpp"
#include "core/constants.hpp"
#include "features/routing/dispatcher.hpp"
#include "features/routing/router.hpp"
#include "infra/json.hpp"
#include "transport/internet/inbound_listen.hpp"
#include "transport/internet/proxy_protocol.hpp"
#include "transport/internet/stream_settings.hpp"

#include <array>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

// ============================================================================
// 资源限制配置
// ============================================================================
struct LimitsConfig {
    uint32_t max_connections = defaults::kMaxConnections;
    uint32_t max_connections_per_ip = defaults::kMaxConnectionsPerIP;
    AuthFailureLimitConfig ip_ban;

    static LimitsConfig FromJson(const json::object& j);
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
    uint32_t uplink_only = defaults::kUplinkOnlyTimeout;    // 下行关闭后上行最多保留多久
    uint32_t downlink_only = defaults::kDownlinkOnlyTimeout;// 上行关闭后下行最多保留多久

    [[nodiscard]] std::chrono::seconds HandshakeTimeout() const noexcept {
        return std::chrono::seconds(handshake);
    }

    [[nodiscard]] std::chrono::seconds DialTimeout() const noexcept {
        return std::chrono::seconds(dial);
    }

    [[nodiscard]] std::chrono::seconds WriteTimeout() const noexcept {
        return std::chrono::seconds(write);
    }

    [[nodiscard]] std::chrono::seconds IdleTimeout() const noexcept {
        return std::chrono::seconds(idle);
    }

    [[nodiscard]] std::chrono::seconds UplinkOnlyTimeout() const noexcept {
        return std::chrono::seconds(uplink_only);
    }

    [[nodiscard]] std::chrono::seconds DownlinkOnlyTimeout() const noexcept {
        return std::chrono::seconds(downlink_only);
    }

    static TimeoutsConfig FromJson(const json::object& j);
};

// ============================================================================
// 路由规则配置
// ============================================================================
struct RoutingPortRange {
    uint16_t start = 0;
    uint16_t end = 0;
};

class RoutingIpNetwork {
public:
    RoutingIpNetwork(const RoutingIpNetwork&) = default;
    RoutingIpNetwork& operator=(const RoutingIpNetwork&) = default;
    RoutingIpNetwork(RoutingIpNetwork&&) noexcept = default;
    RoutingIpNetwork& operator=(RoutingIpNetwork&&) noexcept = default;

    [[nodiscard]] const std::array<uint8_t, 16>& Network() const noexcept {
        return network_;
    }
    [[nodiscard]] uint8_t Prefix() const noexcept { return prefix_; }
    [[nodiscard]] bool IsV6() const noexcept { return is_v6_; }
    [[nodiscard]] static std::optional<RoutingIpNetwork> Parse(
        std::string_view value);

private:
    RoutingIpNetwork() = default;

    std::array<uint8_t, 16> network_{};
    uint8_t prefix_ = 0;
    bool is_v6_ = false;
};

struct RouteRuleConfig {
    // 匹配条件（可多选）
    std::vector<std::string> domain_suffix;  // 域名后缀
    std::vector<std::string> domain_keyword; // 域名关键词
    std::vector<std::string> domain_full;    // 完整域名
    std::vector<std::string> domain_regex;   // 正则域名
    std::vector<std::string> geosite;        // GeoSite tag (e.g., "cn", "category-ads")
    std::vector<RoutingIpNetwork> ip;        // 归一化后的目标 IP 网络
    std::vector<std::string> geoip;          // GeoIP tag (e.g., "cn", "private")
    std::vector<RoutingPortRange> port;       // 归一化后的目标端口区间
    std::vector<std::string> network;        // 网络类型 (tcp/udp)
    std::vector<std::string> inbound_tag;    // 入站标签
    std::vector<std::string> user;           // 用户 email
    std::vector<RoutingIpNetwork> source;    // 归一化后的来源 IP 网络
    std::vector<RoutingPortRange> source_port; // 归一化后的来源端口区间
    std::vector<std::string> protocol;       // 嗅探协议 (http/tls/bittorrent)

    std::string outbound_tag;                // 目标出站

    static RouteRuleConfig FromJson(const json::object& j);
};

struct RoutingConfig {
    routing::DomainStrategy domain_strategy = routing::DomainStrategy::AsIs;
    std::vector<RouteRuleConfig> rules;

    static RoutingConfig FromJson(const json::object& j);
};

// ============================================================================
// 日志配置
// ============================================================================
struct LogConfig {
    std::string level = std::string(constants::logging::kDefaultLevel);  // none/trace/debug/info/warning(warn)/error
    std::filesystem::path log_dir = std::filesystem::path(constants::paths::kDefaultLogDir);
    std::filesystem::path access_path;
    std::filesystem::path error_path;
    uint16_t max_days = defaults::kLogRetentionDays;  // 日志保留天数（按天切割）
    bool rotate_daily = true;                         // 按本地日期切割日志
    bool gzip = true;                                 // 历史日志 gzip 压缩

    static LogConfig FromJson(const json::object& j);
};

// ============================================================================
// DNS 配置
// ============================================================================
struct DnsConfig {
    std::vector<udp::endpoint> servers{
        {net::ip::address_v4({8, 8, 8, 8}), 53},
        {net::ip::address_v4({1, 1, 1, 1}), 53},
    };
    uint32_t timeout = defaults::kDnsTimeout;
    uint32_t cache_size = defaults::kDnsCacheSize;
    uint32_t min_ttl = defaults::kDnsMinTTL;
    uint32_t max_ttl = defaults::kDnsMaxTTL;

    static DnsConfig FromJson(const json::object& j);
};

// ============================================================================
// 入站配置
// ============================================================================

// How a Shadowsocks 2022 user credential becomes its user key. Static sources
// carry base64 PSKs; panels carry user UUIDs from which SS2022 keys derive.
enum class Ss2022UserKey : uint8_t {
    Base64Psk,
    UuidDerived,
};

// Protocol-specific inbound source fields. Every source maps its own field
// names into this one shape; protocols parse it once on the cold path.
struct InboundProtocolSettings {
    std::string method = std::string(constants::protocol::kAes256Gcm);
    // SS2022 server identity PSK (EIH). Empty disables the identity header.
    std::string identity_password;
    Ss2022UserKey ss2022_user_key = Ss2022UserKey::Base64Psk;
    std::string padding_scheme;
    std::string vless_decryption = std::string(constants::protocol::kNone);
    uint32_t hysteria_up_mbps = 0;
    uint32_t hysteria_down_mbps = 0;
};

// One authenticated user. `credential` is already the protocol credential
// (UUID, password or PSK); sources resolve their own field aliases.
struct InboundUserSpec {
    int64_t user_id = 0;
    std::string email;
    std::string credential;
    std::string flow;
    uint64_t speed_limit = 0;
    uint32_t device_limit = 0;
};

// The source-neutral inbound aggregate. Panel and static sources both map to
// it; the shared builder prepares runtime state only from this value.
struct InboundSpec {
    std::string tag;
    std::vector<std::string> all_tags;
    // Opaque reporting identity; empty disables per-user reporting.
    std::string accounting_key;
    std::string protocol;
    InboundListen listen;
    uint16_t port = 0;
    ProxyProtocolMode proxy_protocol = ProxyProtocolMode::Auto;
    InboundProtocolSettings settings;
    std::vector<InboundUserSpec> users;
    // Normalized and validated by the source's shared field parsers.
    StreamSettings stream_settings;
    SniffConfig sniffing;
    routing::OutboundSelectionPolicy outbound_policy{
        routing::ForceOutbound(std::string(constants::protocol::kDirect))};
};

// Static inbound source as written in inbounds.json. Only tag fallback and
// outbound selection remain static-specific; the rest maps 1:1 to InboundSpec.
struct StaticInboundConfig {
    std::vector<std::string> tags;
    std::string protocol;
    InboundListen listen;
    uint16_t port = 0;
    InboundProtocolSettings settings;
    std::vector<InboundUserSpec> users;
    StreamSettings stream_settings;
    SniffConfig sniffing;
    ProxyProtocolMode proxy_protocol = ProxyProtocolMode::Auto;
    bool routing_enabled = false;
    std::optional<std::string> outbound_tag;
    static StaticInboundConfig FromJson(const json::object& j);
};

namespace infra {

struct OutboundSourceConfig {
    std::string tag;
    std::string protocol;
    json::object settings;
    StreamSettings stream_settings;
    std::optional<OutboundBind> send_through;
    bool passthrough = false;
    static OutboundSourceConfig FromJson(const json::object& j);
};

}  // namespace infra

