#pragma once

#include "acppnode/protocol/outbound.hpp"
#include "acppnode/protocol/trojan/trojan_protocol.hpp"
#include "acppnode/handlers/outbound_handler.hpp"

namespace acpp {

// 前向声明
class IDnsService;

// ============================================================================
// Trojan Outbound 协议处理器（三层架构协议层）
//
// Handshake = 发送 SHA224(password)\r\nCMD ATYPE ADDR PORT\r\n 请求头
// WrapStream = 透传（TLS 已由传输层完成，协议头已在 Handshake 发出）
// ============================================================================
class TrojanOutboundHandler final : public IOutboundHandler {
public:
    explicit TrojanOutboundHandler(std::string password)
        : password_(std::move(password)) {}

    cobalt::task<OutboundHandshakeResult> Handshake(
        AsyncStream& stream,
        const SessionContext& ctx,
        std::span<const uint8_t> initial_payload) override;

    cobalt::task<OutboundWrapResult> WrapStream(
        std::unique_ptr<AsyncStream> stream,
        const SessionContext& ctx) override {
        (void)ctx;
        co_return OutboundWrapResult(std::move(stream));  // 透传
    }

private:
    std::string password_;
};

// ============================================================================
// Trojan Outbound 配置
// ============================================================================
struct TrojanOutboundConfig {
    std::string tag;                // 出站标识
    std::string address;            // 服务器地址
    uint16_t port = 443;            // 服务器端口
    std::string password;           // 密码
    
    // TLS 配置
    std::string server_name;        // SNI（默认使用 address）
    bool allow_insecure = false;    // 是否允许不验证证书
    std::vector<std::string> alpn;  // ALPN 协议列表

    // 传输层配置（保持现有 streamSettings JSON）
    StreamSettings stream_settings;
    
    // 连接配置
    std::chrono::seconds timeout{10};
    
    std::string GetServerName() const {
        return server_name.empty() ? address : server_name;
    }
};

// ============================================================================
// Trojan Outbound 实现
// ============================================================================
class TrojanOutbound final : public IOutbound {
public:
    TrojanOutbound(net::any_io_executor executor,
                   const TrojanOutboundConfig& config,
                   IDnsService* dns_service);

    ~TrojanOutbound() override;

    // 仅返回传输目标，由 TransportDialer 统一执行 TCP/TLS/WS
    cobalt::task<std::expected<OutboundTransportTarget, ErrorCode>>
        ResolveTransportTarget(SessionContext& ctx) override;

    std::string Tag() const override { return config_.tag; }
    IOutboundHandler* GetOutboundHandler() override { return handler_.get(); }

private:
    TrojanOutboundConfig config_;
    IDnsService* dns_service_;
    std::unique_ptr<TrojanOutboundHandler> handler_;
};

// ============================================================================
// 创建 Trojan Outbound 的工厂函数
// ============================================================================
std::unique_ptr<IOutbound> CreateTrojanOutbound(
    net::any_io_executor executor,
    const TrojanOutboundConfig& config,
    IDnsService* dns_service);

}  // namespace acpp
