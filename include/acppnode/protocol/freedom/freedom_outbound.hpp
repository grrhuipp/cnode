#pragma once

#include "acppnode/protocol/outbound.hpp"
#include "acppnode/handlers/outbound_handler.hpp"
#include "acppnode/dns/dns_service.hpp"

namespace acpp {

// Forward declaration
class UDPSessionManager;

// ============================================================================
// Freedom 出站设置
// ============================================================================
struct FreedomSettings {
    std::string send_through = "auto";   // auto / 0.0.0.0 / 具体 IPv4
    std::string domain_strategy = "AsIs"; // AsIs / UseIP / UseIPv4
    std::string redirect;                 // 重定向目标 "host:port"（空=不重定向）
    bool enable_udp = true;               // 是否启用 UDP
    int udp_timeout = 300;                // UDP 会话超时（秒）
};

// ============================================================================
// Freedom Outbound 协议处理器（三层架构协议层）
//
// Freedom 直连无协议头，Handshake 是 noop，WrapStream 透传。
// initial_payload 由 SessionHandler 统一通过 DoRelayWithFirstPacket 发送。
// ============================================================================
class FreedomOutboundHandler final : public IOutboundHandler {
public:
    cobalt::task<OutboundHandshakeResult> Handshake(
        AsyncStream& stream,
        const SessionContext& ctx,
        std::span<const uint8_t> initial_payload) override {
        (void)stream;
        (void)ctx;
        (void)initial_payload;
        co_return {};  // Freedom 无协议头
    }

    cobalt::task<OutboundWrapResult> WrapStream(
        std::unique_ptr<AsyncStream> stream,
        const SessionContext& ctx) override {
        (void)ctx;
        co_return OutboundWrapResult(std::move(stream));  // 透传
    }
};

// ============================================================================
// Freedom Outbound - 直连出站
// ============================================================================
class FreedomOutbound final : public IOutbound {
public:
    FreedomOutbound(const std::string& tag,
                    const FreedomSettings& settings,
                    IDnsService* dns_service,
                    UDPSessionManager* udp_session_manager,  // Per-worker UDP manager
                    std::chrono::seconds dial_timeout = std::chrono::seconds(10));

    cobalt::task<std::expected<OutboundTransportTarget, ErrorCode>>
        ResolveTransportTarget(SessionContext& ctx) override;

    // UDP 拨号（Full Cone NAT）
    cobalt::task<UDPDialResult> DialUDP(
        SessionContext& ctx,
        net::any_io_executor executor,
        std::function<void(const UDPPacket&)> on_packet) override;

    std::string Tag() const override { return tag_; }
    std::string SendThrough() const override { return settings_.send_through; }
    bool SupportsUDP() const override { return settings_.enable_udp; }
    IOutboundHandler* GetOutboundHandler() override { return &handler_; }

private:
    // 解析目标地址列表（保留多 IP 顺序，按策略过滤/排序）
    cobalt::task<std::expected<std::vector<net::ip::address>, ErrorCode>>
    ResolveTargets(SessionContext& ctx);

    // 确定本地绑定地址
    std::optional<net::ip::address> DetermineLocalAddress(
        const SessionContext& ctx,
        const net::ip::address& remote_addr);

    std::string tag_;
    FreedomSettings settings_;
    IDnsService* dns_service_;
    UDPSessionManager* udp_session_manager_;  // Per-worker UDP manager
    std::chrono::seconds dial_timeout_;
    StreamSettings stream_settings_;          // 默认 tcp/none
    FreedomOutboundHandler handler_;
};

// ============================================================================
// 创建 Freedom Outbound 的工厂函数
// ============================================================================
std::unique_ptr<IOutbound> CreateFreedomOutbound(
    const std::string& tag,
    const FreedomSettings& settings,
    IDnsService* dns_service,
    UDPSessionManager* udp_session_manager,  // Per-worker UDP manager
    std::chrono::seconds dial_timeout = std::chrono::seconds(10));

}  // namespace acpp
