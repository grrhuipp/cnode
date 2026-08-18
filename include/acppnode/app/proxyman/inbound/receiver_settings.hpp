#pragma once

#include "acppnode/features/routing/dispatch_policy.hpp"
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
// 出站选择策略和 limiter 这些 receiver 语义。冷路径构建；inbound Handler
// 热路径只读，Dispatcher 只接收其中的窄 DispatchPolicy。
// ============================================================================
struct ReceiverSettings {
    std::string      inbound_tag;             // 主标签（map key）
    std::vector<std::string> inbound_tags;   // 所有标签（路由匹配任一）
    std::string      protocol;          // "vmess" / "trojan" 等协议名
    StreamSettings   stream_settings;  // 传输层配置（network/security）
    routing::DispatchPolicy dispatch_policy;
    ProxyProtocolMode proxy_protocol = ProxyProtocolMode::Auto; // PROXY Protocol 处理模式
    bool             has_route_inbound_tags = false;  // 构建期归一化，热入口只读位
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
    routing::OutboundSelectionPolicy outbound_policy = {},
    uint32_t access_source_ref = 0) {
    ReceiverSettings settings;
    settings.inbound_tag     = std::move(inbound_tag);
    settings.inbound_tags    = std::move(inbound_tags);
    settings.protocol        = std::move(protocol);
    settings.stream_settings = std::move(stream_settings);
    settings.dispatch_policy.sniffing = std::move(sniff_config);
    settings.dispatch_policy.sniffing.RefreshHotPathFields();
    settings.dispatch_policy.outbound = std::move(outbound_policy);
    settings.proxy_protocol  = proxy_protocol;
    settings.has_route_inbound_tags =
        !settings.inbound_tags.empty() &&
        !(settings.inbound_tags.size() == 1 &&
          settings.inbound_tags.front() == settings.inbound_tag);
    settings.limiter         = limiter;
    settings.access_source_ref = access_source_ref;
    return settings;
}

}  // namespace acpp::proxyman::inbound
