#pragma once

#include "features/routing/dispatch_policy.hpp"
#include "transport/internet/proxy_protocol_mode.hpp"
#include "transport/internet/stream_settings.hpp"

#include <string>
#include <utility>
#include <vector>

namespace proxyman::inbound {

// ============================================================================
// ReceiverSettings - xray-style proxyman receiver settings
//
// 对齐 xray-core app/proxyman ReceiverConfig 的职责：监听、传输、嗅探、
// 出站选择策略这些 receiver 语义。冷路径构建；inbound Handler
// 热路径只读，Dispatcher 只接收其中的窄 DispatchPolicy。
// ============================================================================
struct ReceiverSettings {
    std::string      inbound_tag;             // 主标签（map key）
    std::vector<std::string> inbound_tags;   // 所有标签（路由匹配任一）
    std::string      protocol;          // "vmess" / "trojan" 等协议名
    std::string      accounting_key{};  // Opaque stable reporting identity; empty disables per-user reporting.
    StreamSettings   stream_settings;  // 传输层配置（network/security）
    routing::DispatchPolicy dispatch_policy;
    ProxyProtocolMode proxy_protocol = ProxyProtocolMode::Auto;
    bool             has_route_inbound_tags = false;  // 构建期归一化，热入口只读位

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
    ProxyProtocolMode proxy_protocol,
    routing::OutboundSelectionPolicy outbound_policy,
    std::string accounting_key) {
    const bool has_route_inbound_tags =
        !inbound_tags.empty() &&
        !(inbound_tags.size() == 1 && inbound_tags.front() == inbound_tag);
    return ReceiverSettings{
        .inbound_tag = std::move(inbound_tag),
        .inbound_tags = std::move(inbound_tags),
        .protocol = std::move(protocol),
        .accounting_key = std::move(accounting_key),
        .stream_settings = std::move(stream_settings),
        .dispatch_policy = {
            .sniffing = std::move(sniff_config),
            .outbound = std::move(outbound_policy),
        },
        .proxy_protocol = proxy_protocol,
        .has_route_inbound_tags = has_route_inbound_tags,
    };
}

}  // namespace proxyman::inbound
