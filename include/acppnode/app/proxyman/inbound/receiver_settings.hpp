#pragma once

#include "acppnode/proxy/sniff_config.hpp"
#include "acppnode/transport/internet/proxy_protocol_mode.hpp"
#include "acppnode/transport/internet/stream_settings.hpp"

#include <string>
#include <utility>
#include <vector>

namespace acpp {
class ConnectionLimiter;
}

namespace acpp::proxyman::inbound {

// ============================================================================
// ReceiverSettings - xray-style proxyman receiver settings
//
// 对齐 xray-core app/proxyman ReceiverConfig 的职责：监听、传输、嗅探、
// 固定出站和 limiter 这些 receiver 语义。冷路径构建；inbound Handler
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
    bool             has_fixed_outbound = false;       // fixed_outbound_tag 是否非空
    // 非空时跳过路由；dispatcher 通过 outbound manager 按 tag 获取 handler。
    std::string      fixed_outbound_tag;
    bool             has_route_fallback_outbound = false;
    // 非空时不跳过路由，只作为 routing.json 未命中时的默认 outbound。
    std::string      route_fallback_outbound_tag;
    ConnectionLimiter* limiter = nullptr;      // Worker 私有 limiter，非拥有指针。

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
    std::string fixed_outbound = {},
    ProxyProtocolMode proxy_protocol = ProxyProtocolMode::Auto,
    std::string route_fallback_outbound = {}) {
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
    settings.has_fixed_outbound = !fixed_outbound.empty();
    settings.fixed_outbound_tag = std::move(fixed_outbound);
    settings.has_route_fallback_outbound = !route_fallback_outbound.empty();
    settings.route_fallback_outbound_tag = std::move(route_fallback_outbound);
    settings.limiter         = limiter;
    return settings;
}

}  // namespace acpp::proxyman::inbound
