#pragma once

#include "acppnode/common/defaults.hpp"
#include "acppnode/core/constants.hpp"
#include "acppnode/infra/json.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace acpp {

// ============================================================================
// 资源限制配置
// ============================================================================
struct LimitsConfig {
    uint32_t max_connections = defaults::kMaxConnections;
    uint32_t max_connections_per_ip = defaults::kMaxConnectionsPerIP;
    size_t buffer_size = defaults::kBufferSize;

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

    static TimeoutsConfig FromJson(const json::object& j);
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

    static RouteRuleConfig FromJson(const json::object& j);
};

struct RoutingConfig {
    std::string domain_strategy = std::string(constants::protocol::kAsIs);
    std::vector<RouteRuleConfig> rules;

    static RoutingConfig FromJson(const json::object& j);
};

}  // namespace acpp
