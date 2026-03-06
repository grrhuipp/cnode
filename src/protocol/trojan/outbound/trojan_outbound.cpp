#include "acppnode/protocol/trojan/outbound/trojan_outbound.hpp"
#include "acppnode/protocol/protocol_registry.hpp"
#include "acppnode/protocol/outbound_helpers.hpp"
#include "acppnode/transport/stream_helpers.hpp"
#include "acppnode/dns/dns_service.hpp"
#include "acppnode/infra/json_helpers.hpp"
#include "acppnode/infra/log.hpp"

#include <array>

namespace acpp {

// ============================================================================
// TrojanOutbound 实现
// ============================================================================

TrojanOutbound::TrojanOutbound(net::any_io_executor executor,
                               const TrojanOutboundConfig& config,
                               IDnsService* dns_service)
    : config_(config)
    , dns_service_(dns_service) {
    (void)executor;
    config_.stream_settings.RecomputeModes();

    handler_ = std::make_unique<TrojanOutboundHandler>(config_.password);
}

TrojanOutbound::~TrojanOutbound() = default;

cobalt::task<std::expected<OutboundTransportTarget, ErrorCode>>
TrojanOutbound::ResolveTransportTarget(SessionContext& ctx) {
    try {
        auto addr_result = co_await ResolveOutboundAddress(config_.address, dns_service_);
        if (!addr_result) {
            LOG_CONN_DEBUG(ctx, "[TrojanOutbound] DNS resolve failed for {}", config_.address);
            co_return std::unexpected(addr_result.error());
        }
        auto addr = *addr_result;
        ctx.resolved_ip = addr;

        OutboundTransportTarget target;
        target.host = addr.to_string();
        target.port = config_.port;
        target.timeout = config_.timeout;
        target.stream_settings = &config_.stream_settings;
        target.server_name = config_.GetServerName();
        co_return target;

    } catch (const std::exception& e) {
        LOG_CONN_DEBUG(ctx, "[TrojanOutbound] resolve target exception: {}", e.what());
        co_return std::unexpected(ErrorCode::OUTBOUND_CONNECTION_FAILED);
    }
}

// ============================================================================
// TrojanOutboundHandler 实现
// ============================================================================

cobalt::task<OutboundHandshakeResult> TrojanOutboundHandler::Handshake(
    AsyncStream& stream,
    const SessionContext& ctx,
    std::span<const uint8_t> initial_payload) {
    (void)initial_payload;

    const auto& target = ctx.EffectiveTarget();

    // 构建 Trojan 请求头（不含 initial_payload，数据由 DoRelayWithFirstPacket 单独发送）
    std::array<uint8_t, 512> header{};
    size_t header_len = trojan::TrojanCodec::EncodeRequestTo(
        password_, trojan::TrojanCommand::CONNECT, target,
        header.data(), header.size());
    if (header_len == 0) {
        LOG_CONN_FAIL_CTX(ctx, "TrojanOutboundHandler: Handshake encode failed");
        co_return std::unexpected(ErrorCode::PROTOCOL_ENCODE_FAILED);
    }

    try {
        if (!co_await acpp::WriteFull(stream, header.data(), header_len)) {
            LOG_CONN_FAIL_CTX(ctx, "TrojanOutboundHandler: Handshake write failed");
            co_return std::unexpected(ErrorCode::SOCKET_WRITE_FAILED);
        }

        LOG_CONN_DEBUG(ctx, "[Trojan] Handshake sent {} bytes", header_len);
        co_return {};
    } catch (const boost::system::system_error& e) {
        co_return std::unexpected(MapAsioError(e.code()));
    } catch (...) {
        co_return std::unexpected(ErrorCode::SOCKET_WRITE_FAILED);
    }
}

// ============================================================================
// 工厂函数
// ============================================================================

std::unique_ptr<IOutbound> CreateTrojanOutbound(
    net::any_io_executor executor,
    const TrojanOutboundConfig& config,
    IDnsService* dns_service) {
    
    return std::make_unique<TrojanOutbound>(executor, config, dns_service);
}

}  // namespace acpp

// ============================================================================
// 自注册（静态初始化，Xray init() 设计）
// ============================================================================
namespace {
const bool kTrojanRegistered = (acpp::OutboundFactory::Instance().Register(
    "trojan",
    [](const acpp::OutboundConfig& cfg,
       acpp::net::any_io_executor executor,
       acpp::IDnsService* dns,
       acpp::UDPSessionManager* /*udp_mgr*/,
       std::chrono::seconds timeout) -> std::unique_ptr<acpp::IOutbound> {
        const auto& s = cfg.settings;

        acpp::TrojanOutboundConfig trojan_config;
        trojan_config.tag     = cfg.tag;
        trojan_config.timeout = timeout;

        // Xray 格式: servers[0] 包含 address/port/password 等
        const auto* servers_p = s.if_contains("servers");
        if (servers_p && servers_p->is_array() && !servers_p->as_array().empty()) {
            const auto& srv = servers_p->as_array()[0].as_object();
            trojan_config.address     = acpp::json::GetString(srv, "address", "");
            trojan_config.port        = static_cast<uint16_t>(acpp::json::GetInt(srv, "port", 443));
            trojan_config.password    = acpp::json::GetString(srv, "password", "");
            trojan_config.server_name = acpp::json::GetString(srv, "serverName", "");
            trojan_config.allow_insecure = acpp::json::GetBool(srv, "allowInsecure", false);
        } else {
            // 兼容旧扁平格式
            trojan_config.address     = acpp::json::GetString(s, "Address",     "address",    "");
            trojan_config.port        = static_cast<uint16_t>(acpp::json::GetInt(s, "Port", "port", 443));
            trojan_config.password    = acpp::json::GetString(s, "Password",    "password",   "");
            trojan_config.server_name = acpp::json::GetString(s, "ServerName",  "serverName", "");
            trojan_config.allow_insecure = acpp::json::GetBool(s, "AllowInsecure", "allowInsecure", false);
        }
        trojan_config.stream_settings = cfg.stream_settings;
        trojan_config.stream_settings.RecomputeModes();
        if (!trojan_config.stream_settings.IsTls()) {
            // Trojan 默认启用 TLS，保持旧行为
            trojan_config.stream_settings.security = "tls";
            trojan_config.stream_settings.RecomputeModes();
        }
        trojan_config.stream_settings.tls.server_name = trojan_config.GetServerName();
        trojan_config.stream_settings.tls.allow_insecure = trojan_config.allow_insecure;
        if (!trojan_config.alpn.empty()) {
            trojan_config.stream_settings.tls.alpn = trojan_config.alpn;
        }

        if (trojan_config.address.empty() || trojan_config.password.empty()) {
            return nullptr;  // 配置不完整
        }

        return acpp::CreateTrojanOutbound(executor, trojan_config, dns);
    }), true);
}  // namespace
