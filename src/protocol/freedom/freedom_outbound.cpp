#include "acppnode/protocol/freedom/freedom_outbound.hpp"
#include "acppnode/common/ip_utils.hpp"
#include "acppnode/protocol/protocol_registry.hpp"
#include "acppnode/transport/tcp_stream.hpp"
#include "acppnode/app/udp_session.hpp"
#include "acppnode/infra/json_helpers.hpp"
#include "acppnode/infra/log.hpp"
#include <format>

namespace acpp {

namespace {

std::string SelectUdpBindAddress(
    const FreedomSettings& settings,
    const SessionContext& ctx) {
    if (!settings.send_through.empty() &&
        settings.send_through != "auto" &&
        !iputil::IsWildcardBindAddress(settings.send_through)) {
        return settings.send_through;
    }

    if (!ctx.local_ip.is_unspecified()) {
        const auto local_ip = iputil::NormalizeAddress(ctx.local_ip);
        if (local_ip.is_v4()) {
            return local_ip.to_string();
        }
    }

    return "0.0.0.0";
}

std::string MakeUdpSessionId(const std::string& bind_addr) {
    return std::format("udp-{}", bind_addr);
}

}  // namespace

FreedomOutbound::FreedomOutbound(
    const std::string& tag,
    const FreedomSettings& settings,
    IDnsService* dns_service,
    UDPSessionManager* udp_session_manager,
    std::chrono::seconds dial_timeout)
    : tag_(tag)
    , settings_(settings)
    , dns_service_(dns_service)
    , udp_session_manager_(udp_session_manager)
    , dial_timeout_(dial_timeout) {
    stream_settings_.network = "tcp";
    stream_settings_.security = "none";
    stream_settings_.RecomputeModes();
}

cobalt::task<std::expected<OutboundTransportTarget, ErrorCode>>
FreedomOutbound::ResolveTransportTarget(SessionContext& ctx) {
    // redirect：替换目标地址（Xray freedom redirect 语义）
    if (!settings_.redirect.empty()) {
        auto redir = TargetAddress::Parse(settings_.redirect);
        if (redir && redir->IsValid()) {
            LOG_CONN_DEBUG(ctx, "Freedom redirect {} -> {}",
                           ctx.EffectiveTarget().ToString(), redir->ToString());
            ctx.final_target = *redir;
        }
    }

    // 确定目标地址
    const auto& target = ctx.EffectiveTarget();

    if (!target.IsValid()) {
        co_return std::unexpected(ErrorCode::PROTOCOL_INVALID_ADDRESS);
    }

    LOG_CONN_DEBUG(ctx, "Freedom resolve target {}", target.ToString());

    // 解析目标地址列表（保留多 IP，交给 TransportDialer 按顺序尝试）
    auto remote_addrs = co_await ResolveTargets(ctx);
    if (!remote_addrs || remote_addrs->empty()) {
        co_return std::unexpected(remote_addrs ? ErrorCode::DNS_RESOLVE_FAILED : remote_addrs.error());
    }

    OutboundTransportTarget transport_target;
    transport_target.host = target.host;
    transport_target.port = target.port;
    if (settings_.send_through == "auto") {
        transport_target.bind_mode = OutboundTransportTarget::BindMode::Auto;
    } else if (!iputil::IsWildcardBindAddress(settings_.send_through)) {
        transport_target.bind_mode = OutboundTransportTarget::BindMode::Explicit;
    }
    transport_target.candidates.reserve(remote_addrs->size());
    for (const auto& remote_addr : *remote_addrs) {
        OutboundDialCandidate candidate;
        candidate.endpoint = tcp::endpoint(remote_addr, target.port);
        candidate.bind_local = DetermineLocalAddress(ctx, remote_addr);
        transport_target.candidates.push_back(std::move(candidate));
    }
    for (const auto& candidate : transport_target.candidates) {
        if (candidate.bind_local) {
            transport_target.bind_local = candidate.bind_local;
            break;
        }
    }
    transport_target.timeout = dial_timeout_;
    transport_target.stream_settings = &stream_settings_;

    if (transport_target.candidates.size() == 1) {
        const auto& candidate = transport_target.candidates.front();
        if (candidate.bind_local) {
            LOG_CONN_DEBUG(ctx, "Freedom target {}:{} bind {}",
                           candidate.endpoint.address().to_string(),
                           candidate.endpoint.port(),
                           candidate.bind_local->to_string());
        } else {
            LOG_CONN_DEBUG(ctx, "Freedom target {}:{} (system bind)",
                           candidate.endpoint.address().to_string(),
                           candidate.endpoint.port());
        }
    } else {
        LOG_CONN_DEBUG(ctx, "Freedom target {}:{} resolved {} candidates",
                       transport_target.host,
                       transport_target.port,
                       transport_target.candidates.size());
    }

    co_return transport_target;
}

cobalt::task<UDPDialResult> FreedomOutbound::DialUDP(
    SessionContext& ctx,
    net::any_io_executor executor,
    std::function<void(const UDPPacket&)> on_packet) {
    
    if (!settings_.enable_udp) {
        co_return UDPDialResult{ErrorCode::NOT_SUPPORTED, nullptr, nullptr, nullptr, nullptr, ""};
    }
    
    // Per-worker UDP session
    // 同一 worker 上的同一出口 IP 共享一个 UDP socket
    // （已经是 per-worker，不需要 worker_id）
    const std::string bind_addr = SelectUdpBindAddress(settings_, ctx);
    const std::string session_id = MakeUdpSessionId(bind_addr);
    
    try {
        if (!udp_session_manager_) {
            LOG_CONN_FAIL("Freedom UDP: UDPSessionManager not available");
            co_return UDPDialResult{ErrorCode::INTERNAL, nullptr, nullptr, nullptr, nullptr, ""};
        }
        
        // 获取或创建 session（使用当前 executor）
        auto session = udp_session_manager_->GetOrCreateSession(session_id, executor, nullptr, bind_addr);
        
        if (!session) {
            co_return UDPDialResult{ErrorCode::NETWORK_BIND_FAILED, nullptr, nullptr, nullptr, nullptr, ""};
        }
        
        LOG_CONN_DEBUG(ctx, "Freedom UDP session {} port {}", 
                      session_id, session->LocalPort());
        
        // 发送函数（传递 callback_id 用于回包路由）
        auto send_fn = [session](const UDPPacket& packet, uint64_t callback_id) -> cobalt::task<ErrorCode> {
            co_return co_await session->Send(packet, callback_id);
        };
        
        // 全局回调（兼容）
        auto set_cb_fn = [session](std::function<void(const UDPPacket&)> cb) {
            session->SetCallback(std::move(cb));
        };
        
        // 注册回调（返回 callback_id）
        // Per-Worker 简化版：无需 executor 参数
        auto register_fn = [session](const std::string& dest, 
                                     std::function<void(const UDPPacket&)> cb) -> uint64_t {
            return session->RegisterCallback(dest, std::move(cb));
        };
        
        // 取消回调
        auto unregister_fn = [session](uint64_t callback_id) {
            session->UnregisterCallback(callback_id);
        };
        
        co_return UDPDialResult{
            ErrorCode::SUCCESS, 
            send_fn, 
            set_cb_fn, 
            register_fn,
            unregister_fn,
            session_id
        };
        
    } catch (const std::exception& e) {
        LOG_CONN_FAIL("Freedom UDP dial failed: {}", e.what());
        co_return UDPDialResult{ErrorCode::INTERNAL, nullptr, nullptr, nullptr, nullptr, ""};
    }
}

cobalt::task<std::expected<std::vector<net::ip::address>, ErrorCode>>
FreedomOutbound::ResolveTargets(SessionContext& ctx) {
    const auto& target = ctx.EffectiveTarget();

    // 如果目标已经是 IP，直接返回
    if (target.IsIP() && target.resolved_addr) {
        if (!target.resolved_addr->is_v4()) {
            co_return std::unexpected(ErrorCode::PROTOCOL_INVALID_ADDRESS);
        }
        ctx.dns_result = "none";
        co_return std::vector<net::ip::address>{*target.resolved_addr};
    }

    // 尝试解析为 IP
    boost::system::error_code ec;
    auto addr = net::ip::make_address(target.host, ec);
    if (!ec) {
        if (!addr.is_v4()) {
            co_return std::unexpected(ErrorCode::PROTOCOL_INVALID_ADDRESS);
        }
        ctx.dns_result = "none";
        co_return std::vector<net::ip::address>{addr};
    }

    // 需要 DNS 解析
    if (!dns_service_) {
        co_return std::unexpected(ErrorCode::DNS_RESOLVE_FAILED);
    }

    // 根据 domain_strategy 决定是否解析
    if (settings_.domain_strategy == "AsIs") {
        // AsIs 模式：使用系统解析器（通过 TcpStream::Connect 的域名版本）
        // 这里我们还是需要解析，因为需要 IP 来连接
        // 实际上 AsIs 主要影响路由匹配，不影响最终连接
    }

    auto dns_result = co_await dns_service_->Resolve(target.host);

    if (!dns_result.Ok()) {
        ctx.dns_result = "failed";
        co_return std::unexpected(ErrorCode::DNS_RESOLVE_FAILED);
    }

    std::vector<net::ip::address> addresses;
    addresses.reserve(dns_result.addresses.size());
    for (const auto& dns_addr : dns_result.addresses) {
        if (!dns_addr.is_v4()) {
            continue;
        }
        addresses.push_back(dns_addr);
    }

    if (addresses.empty()) {
        ctx.dns_result = "failed";
        co_return std::unexpected(ErrorCode::DNS_NO_RECORD);
    }

    ctx.dns_result = dns_result.from_cache ? "cache" : "resolve";
    co_return addresses;
}

std::optional<net::ip::address> FreedomOutbound::DetermineLocalAddress(
    const SessionContext& ctx,
    const net::ip::address& remote_addr) {
    
    if (settings_.send_through == "auto") {
        // auto 模式：源进源出
        // 使用入站连接的本地 IP 作为出站绑定地址
        // 这样可以实现「哪个 IP 进哪个 IP 出」
        
        auto inbound_local = iputil::NormalizeAddress(ctx.inbound_local_addr.address());
        if (!inbound_local.is_unspecified() && !inbound_local.is_loopback()) {
            if (remote_addr.is_v4() && inbound_local.is_v4()) {
                return inbound_local;
            }
        }
        return std::nullopt;
    }
    
    if (iputil::IsWildcardBindAddress(settings_.send_through)) {
        // 系统自动选择
        return std::nullopt;
    }

    // 具体 IP
    boost::system::error_code ec;
    auto addr = net::ip::make_address(settings_.send_through, ec);
    if (ec) {
        return std::nullopt;
    }
    addr = iputil::NormalizeAddress(addr);
    if (!addr.is_v4()) {
        return std::nullopt;
    }

    if (!remote_addr.is_v4()) {
        return std::nullopt;
    }

    return addr;
}

// ============================================================================
// 工厂函数
// ============================================================================

std::unique_ptr<IOutbound> CreateFreedomOutbound(
    const std::string& tag,
    const FreedomSettings& settings,
    IDnsService* dns_service,
    UDPSessionManager* udp_session_manager,
    std::chrono::seconds dial_timeout) {
    return std::make_unique<FreedomOutbound>(tag, settings, dns_service, udp_session_manager, dial_timeout);
}

}  // namespace acpp

// ============================================================================
// 自注册（静态初始化，Xray init() 设计）
// ============================================================================
namespace {
const bool kFreedomRegistered = (acpp::OutboundFactory::Instance().Register(
    "freedom",
    [](const acpp::OutboundConfig& cfg,
       acpp::net::any_io_executor /*executor*/,
       acpp::IDnsService* dns,
       acpp::UDPSessionManager* udp_mgr,
       std::chrono::seconds timeout) -> std::unique_ptr<acpp::IOutbound> {
        const auto& s = cfg.settings;
        acpp::FreedomSettings settings;

        // 支持 PascalCase 和 camelCase
        settings.send_through    = acpp::json::GetString(s, "SendThrough",    "sendThrough",    "auto");
        settings.domain_strategy = acpp::json::GetString(s, "DomainStrategy", "domainStrategy", "AsIs");
        settings.redirect        = acpp::json::GetString(s, "Redirect",       "redirect",       "");

        // Xray 顶级 sendThrough 优先于 settings 内的
        if (!cfg.send_through.empty()) {
            settings.send_through = cfg.send_through;
        }

        return std::make_unique<acpp::FreedomOutbound>(
            cfg.tag, settings, dns, udp_mgr, timeout);
    }), true);
}  // namespace
