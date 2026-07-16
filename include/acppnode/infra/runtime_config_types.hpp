#pragma once

#include "acppnode/common/defaults.hpp"
#include "acppnode/core/constants.hpp"
#include "acppnode/infra/json.hpp"

#include <array>
#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace acpp {

// ============================================================================
// 资源限制配置
// ============================================================================
struct LimitsConfig {
    uint32_t max_connections = defaults::kMaxConnections;
    uint32_t max_connections_per_ip = defaults::kMaxConnectionsPerIP;

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
    std::vector<std::string> domain;         // 域名匹配
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
    std::string domain_strategy = std::string(constants::protocol::kAsIs);
    std::vector<RouteRuleConfig> rules;

    static RoutingConfig FromJson(const json::object& j);
};

}  // namespace acpp
