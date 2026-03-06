#include "acppnode/protocol/freedom/freedom_outbound.hpp"
#include "acppnode/protocol/protocol_registry.hpp"
#include "acppnode/transport/tcp_stream.hpp"
#include "acppnode/app/udp_session.hpp"
#include "acppnode/infra/json_helpers.hpp"
#include "acppnode/infra/log.hpp"
#include <format>

namespace acpp {

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

    // 解析目标地址
    auto [remote_addr, resolve_err] = co_await ResolveTarget(ctx);
    if (resolve_err != ErrorCode::OK) {
        co_return std::unexpected(resolve_err);
    }

    // 确定本地绑定地址
    auto local_addr = DetermineLocalAddress(ctx, remote_addr);

    OutboundTransportTarget transport_target;
    transport_target.host = remote_addr.to_string();
    transport_target.port = target.port;
    transport_target.bind_local = local_addr;
    transport_target.timeout = dial_timeout_;
    transport_target.stream_settings = &stream_settings_;

    if (local_addr) {
        LOG_CONN_DEBUG(ctx, "Freedom target {}:{} bind {}",
                       transport_target.host, transport_target.port,
                       local_addr->to_string());
    } else {
        LOG_CONN_DEBUG(ctx, "Freedom target {}:{} (system bind)",
                       transport_target.host, transport_target.port);
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
    std::string session_id;
    if (!ctx.local_ip.is_unspecified()) {
        // 多 IP 服务器：按出口 IP 区分
        session_id = std::format("udp-{}", ctx.local_ip.to_string());
    } else {
        // 单 IP：使用默认
        session_id = "udp-default";
    }
    
    // 确定绑定地址
    std::string bind_addr;
    if (settings_.send_through != "auto" && settings_.send_through != "0.0.0.0" 
        && !settings_.send_through.empty()) {
        bind_addr = settings_.send_through;
    } else if (!ctx.local_ip.is_unspecified()) {
        bind_addr = ctx.local_ip.to_string();
    } else {
        bind_addr = "0.0.0.0";
    }
    
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

cobalt::task<std::pair<net::ip::address, ErrorCode>>
FreedomOutbound::ResolveTarget(SessionContext& ctx) {
    const auto& target = ctx.EffectiveTarget();

    // 如果目标已经是 IP，直接返回
    if (target.IsIP() && target.resolved_addr) {
        ctx.dns_result = "none";
        ctx.resolved_ip = *target.resolved_addr;
        co_return std::make_pair(*target.resolved_addr, ErrorCode::OK);
    }

    // 尝试解析为 IP
    boost::system::error_code ec;
    auto addr = net::ip::make_address(target.host, ec);
    if (!ec) {
        ctx.dns_result = "none";
        ctx.resolved_ip = addr;
        co_return std::make_pair(addr, ErrorCode::OK);
    }

    // 需要 DNS 解析
    if (!dns_service_) {
        co_return std::make_pair(net::ip::address(), ErrorCode::DNS_RESOLVE_FAILED);
    }

    // 根据 domain_strategy 决定是否解析
    if (settings_.domain_strategy == "AsIs") {
        // AsIs 模式：使用系统解析器（通过 TcpStream::Connect 的域名版本）
        // 这里我们还是需要解析，因为需要 IP 来连接
        // 实际上 AsIs 主要影响路由匹配，不影响最终连接
    }

    bool prefer_ipv6 = (settings_.domain_strategy == "UseIPv6");
    auto dns_result = co_await dns_service_->Resolve(target.host, prefer_ipv6);

    if (!dns_result.Ok()) {
        ctx.dns_result = "failed";
        co_return std::make_pair(net::ip::address(), ErrorCode::DNS_RESOLVE_FAILED);
    }

    // 选择地址
    net::ip::address selected;
    bool found_v4 = false, found_v6 = false;

    for (const auto& dns_addr : dns_result.addresses) {
        if (dns_addr.is_v4()) {
            if (!found_v4) {
                selected = dns_addr;
                found_v4 = true;
            }
        } else {
            if (!found_v6) {
                if (prefer_ipv6 || !found_v4) {
                    selected = dns_addr;
                }
                found_v6 = true;
            }
        }
    }

    if (selected.is_unspecified() && !dns_result.addresses.empty()) {
        selected = dns_result.addresses[0];
    }

    // 设置 DNS 结果
    ctx.dns_result = dns_result.from_cache ? "cache" : "resolve";
    ctx.resolved_ip = selected;

    co_return std::make_pair(selected, ErrorCode::OK);
}

std::optional<net::ip::address> FreedomOutbound::DetermineLocalAddress(
    const SessionContext& ctx,
    const net::ip::address& remote_addr) {
    
    if (settings_.send_through == "auto") {
        // auto 模式：源进源出
        // 使用入站连接的本地 IP 作为出站绑定地址
        // 这样可以实现「哪个 IP 进哪个 IP 出」
        
        auto inbound_local = ctx.inbound_local_addr.address();
        if (!inbound_local.is_unspecified() && !inbound_local.is_loopback()) {
            // 检查 IP 版本匹配
            if (remote_addr.is_v4() && inbound_local.is_v4()) {
                return inbound_local;
            }
            if (remote_addr.is_v6() && inbound_local.is_v6()) {
                return inbound_local;
            }
            // 版本不匹配，让系统选择
        }
        return std::nullopt;
    }
    
    if (settings_.send_through == "0.0.0.0" || settings_.send_through.empty()) {
        // 系统自动选择
        return std::nullopt;
    }

    // 具体 IP
    boost::system::error_code ec;
    auto addr = net::ip::make_address(settings_.send_through, ec);
    if (ec) {
        return std::nullopt;
    }

    // 检查 IP 版本匹配
    if (remote_addr.is_v4() && addr.is_v6()) {
        return std::nullopt;  // 不能用 IPv6 绑定连接 IPv4
    }
    if (remote_addr.is_v6() && addr.is_v4()) {
        return std::nullopt;  // 不能用 IPv4 绑定连接 IPv6
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
