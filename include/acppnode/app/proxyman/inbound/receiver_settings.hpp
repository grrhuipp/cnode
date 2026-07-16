#pragma once

#include "acppnode/proxy/sniff_config.hpp"
#include "acppnode/transport/internet/proxy_protocol_mode.hpp"
#include "acppnode/transport/internet/stream_settings.hpp"

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace acpp {
class ConnectionLimiter;
}

namespace acpp::proxyman::inbound {

enum class RoutePolicyKind : uint8_t {
    GlobalDefault,
    FixedOutbound,
    RouteWithFallback,
};

struct RoutePolicy {
    RoutePolicyKind kind = RoutePolicyKind::GlobalDefault;
    std::string outbound_tag;

    [[nodiscard]] static RoutePolicy GlobalDefault() {
        return {};
    }

    [[nodiscard]] static RoutePolicy Fixed(std::string tag) {
        if (tag.empty()) {
            return {};
        }
        RoutePolicy policy;
        policy.kind = RoutePolicyKind::FixedOutbound;
        policy.outbound_tag = std::move(tag);
        return policy;
    }

    [[nodiscard]] static RoutePolicy RouteWithFallback(std::string tag) {
        if (tag.empty()) {
            return {};
        }
        RoutePolicy policy;
        policy.kind = RoutePolicyKind::RouteWithFallback;
        policy.outbound_tag = std::move(tag);
        return policy;
    }

    [[nodiscard]] bool HasOutboundTag() const noexcept {
        return !outbound_tag.empty();
    }
};

// ============================================================================
// ReceiverSettings - xray-style proxyman receiver settings
//
// 对齐 xray-core app/proxyman ReceiverConfig 的职责：监听、传输、嗅探、
// 路由策略和 limiter 这些 receiver 语义。冷路径构建；inbound Handler
// 热路径只读。
// ============================================================================
struct ReceiverSettings {
    std::string      inbound_tag;             // 主标签（map key）
    std::vector<std::string> inbound_tags;   // 所有标签（路由匹配任一）
    std::string      protocol;          // "vmess" / "trojan" 等协议名
    StreamSettings   stream_settings;  // 传输层配置（network/security）
    SniffConfig      sniff_config;
    ProxyProtocolMode proxy_protocol = ProxyProtocolMode::Auto; // PROXY Protocol 处理模式
    bool             has_route_inbound_tags = false;  // 构建期归一化，热入口只读位
    RoutePolicy      route_policy;
    ConnectionLimiter* limiter = nullptr;      // Worker 私有 limiter，非拥有指针。
    uint32_t         access_source_ref = 0;    // 集中访问日志来源，0 表示不集中上报。

    [[nodiscard]] const std::vector<std::string>* RouteInboundTags() const noexcept {
        return has_route_inbound_tags ? &inbound_tags : nullptr;
    }
};

[[nodiscard]] inline ReceiverSettings MakeReceiverSettings(
    std::string inbound_tag,
    std::vector<std::string> inbound_tags,
    std::string protocol,
    StreamSettings stream_settings,
    SniffConfig sniff_config,
    ConnectionLimiter* limiter,
    ProxyProtocolMode proxy_protocol = ProxyProtocolMode::Auto,
    RoutePolicy route_policy = {},
    uint32_t access_source_ref = 0) {
    ReceiverSettings settings;
    settings.inbound_tag     = std::move(inbound_tag);
    settings.inbound_tags    = std::move(inbound_tags);
    settings.protocol        = std::move(protocol);
    settings.stream_settings = std::move(stream_settings);
    settings.sniff_config    = std::move(sniff_config);
    settings.sniff_config.RefreshHotPathFields();
    settings.proxy_protocol  = proxy_protocol;
    settings.has_route_inbound_tags =
        !settings.inbound_tags.empty() &&
        !(settings.inbound_tags.size() == 1 &&
          settings.inbound_tags.front() == settings.inbound_tag);
    settings.route_policy    = std::move(route_policy);
    settings.limiter         = limiter;
    settings.access_source_ref = access_source_ref;
    return settings;
}

}  // namespace acpp::proxyman::inbound
