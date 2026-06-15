#include "acppnode/proxy/freedom/freedom_outbound.hpp"
#include "acppnode/app/dns/dns.hpp"
#include "acppnode/app/relay.hpp"
#include "acppnode/common/ip_utils.hpp"
#include "acppnode/common/session.hpp"
#include "acppnode/app/proxyman/outbound/factory.hpp"
#include "../../app/proxyman/outbound/source_config.hpp"
#include "acppnode/app/udp_session.hpp"
#include "acppnode/transport/internet/transport_dialer.hpp"
#include "acppnode/infra/log.hpp"

#include <cctype>

namespace acpp::freedom::outbound {

namespace {

std::string LowerAscii(std::string_view value) {
    std::string lower;
    lower.reserve(value.size());
    for (const auto ch : value) {
        lower.push_back(static_cast<char>(
            std::tolower(static_cast<unsigned char>(ch))));
    }
    return lower;
}

Handler::DomainStrategy ParseDomainStrategy(std::string_view value) {
    const auto lower = LowerAscii(value);
    if (lower == LowerAscii(constants::protocol::kUseIP)) {
        return Handler::DomainStrategy::UseIP;
    }
    if (lower == LowerAscii(constants::protocol::kUseIPv6v4)) {
        return Handler::DomainStrategy::UseIPv6v4;
    }
    if (lower == LowerAscii(constants::protocol::kUseIPv6)) {
        return Handler::DomainStrategy::UseIPv6;
    }
    if (lower == LowerAscii(constants::protocol::kUseIPv4v6)) {
        return Handler::DomainStrategy::UseIPv4v6;
    }
    if (lower == LowerAscii(constants::protocol::kUseIPv4)) {
        return Handler::DomainStrategy::UseIPv4;
    }
    if (lower == LowerAscii(constants::protocol::kForceIP)) {
        return Handler::DomainStrategy::ForceIP;
    }
    if (lower == LowerAscii(constants::protocol::kForceIPv6v4)) {
        return Handler::DomainStrategy::ForceIPv6v4;
    }
    if (lower == LowerAscii(constants::protocol::kForceIPv6)) {
        return Handler::DomainStrategy::ForceIPv6;
    }
    if (lower == LowerAscii(constants::protocol::kForceIPv4v6)) {
        return Handler::DomainStrategy::ForceIPv4v6;
    }
    if (lower == LowerAscii(constants::protocol::kForceIPv4)) {
        return Handler::DomainStrategy::ForceIPv4;
    }
    return Handler::DomainStrategy::AsIs;
}

bool AcceptsIPv4(Handler::DomainStrategy strategy) {
    switch (strategy) {
        case Handler::DomainStrategy::UseIPv6:
        case Handler::DomainStrategy::ForceIPv6:
            return false;
        default:
            return true;
    }
}

bool AcceptsIPv6(Handler::DomainStrategy strategy) {
    switch (strategy) {
        case Handler::DomainStrategy::UseIPv4:
        case Handler::DomainStrategy::ForceIPv4:
            return false;
        default:
            return true;
    }
}

bool PreferIPv6First(Handler::DomainStrategy strategy) {
    switch (strategy) {
        case Handler::DomainStrategy::UseIPv6v4:
        case Handler::DomainStrategy::ForceIPv6v4:
            return true;
        default:
            return false;
    }
}

bool PreservesDnsOrder(Handler::DomainStrategy strategy) {
    switch (strategy) {
        case Handler::DomainStrategy::AsIs:
        case Handler::DomainStrategy::UseIP:
        case Handler::DomainStrategy::ForceIP:
            return true;
        default:
            return false;
    }
}

std::string SelectUdpBindAddress(
    const FreedomSettings& settings,
    const session::Context& ctx) {
    const bool auto_bind = settings.send_through == constants::binding::kAuto;
    if (!settings.send_through.empty() &&
        !auto_bind &&
        !iputil::IsWildcardBindAddress(settings.send_through)) {
        return settings.send_through;
    }

    const auto& target = ctx.outbound.target;
    if (auto_bind && ctx.inbound.local_endpoint) {
        const auto inbound_local =
            iputil::NormalizeAddress(ctx.inbound.local_endpoint->address());
        const bool target_is_v6 =
            (target.resolved_addr && target.resolved_addr->is_v6()) ||
            target.type == AddressType::IPv6;
        const bool target_is_v4 =
            (target.resolved_addr && target.resolved_addr->is_v4()) ||
            target.type == AddressType::IPv4;
        if (!inbound_local.is_unspecified() && !inbound_local.is_loopback() &&
            ((target_is_v4 && inbound_local.is_v4()) ||
             (target_is_v6 && inbound_local.is_v6()) ||
             target.type == AddressType::Domain)) {
            return inbound_local.to_string();
        }
    }

    if ((target.resolved_addr && target.resolved_addr->is_v6()) ||
        target.type == AddressType::IPv6) {
        return "::";
    }

    return std::string(constants::network::kAnyIpv4);
}

std::string MakeUdpSessionId(const std::string& bind_addr) {
    std::string session_id;
    session_id.reserve(4 + bind_addr.size());
    session_id.append("udp-");
    session_id.append(bind_addr);
    return session_id;
}

}  // namespace

Handler::Handler(
    const std::string& tag,
    const FreedomSettings& settings,
    ::acpp::app::dns::DNS& dns_service,
    UDPSessionManager* udp_session_manager,
    std::chrono::seconds dial_timeout)
    : tag_(tag)
    , settings_(settings)
    , dns_service_(dns_service)
    , udp_session_manager_(udp_session_manager)
    , dial_timeout_(dial_timeout) {
    if (!settings_.redirect.empty()) {
        auto redir = TargetAddress::Parse(settings_.redirect);
        if (redir && redir->IsValid()) {
            redirect_target_ = std::move(*redir);
            redirect_target_text_ = redirect_target_->ToString();
        }
    }

    if (settings_.send_through == constants::binding::kAuto) {
        bind_mode_ = OutboundTransportTarget::BindMode::Auto;
    } else if (!iputil::IsWildcardBindAddress(settings_.send_through)) {
        bind_mode_ = OutboundTransportTarget::BindMode::Explicit;
        IoErrorCode ec;
        auto addr = net::ip::make_address(settings_.send_through, ec);
        if (!ec) {
            explicit_send_through_addr_ = addr;
            explicit_udp_bind_addr_ = settings_.send_through;
            explicit_udp_session_id_ = MakeUdpSessionId(*explicit_udp_bind_addr_);
        }
    }

    domain_strategy_ = ParseDomainStrategy(settings_.domain_strategy);

    stream_settings_.network = std::string(constants::protocol::kTcp);
    stream_settings_.security = std::string(constants::protocol::kNone);
    stream_settings_.RecomputeModes();
}

net::awaitable<OutboundProcessResult> Handler::Process(
    net::io_context& io_context,
    const tcp::endpoint* inbound_local_addr,
    session::Context& ctx,
    const TimeoutsConfig& /*timeouts*/,
    transport::Link inbound,
    StatsShard& stats,
    const RelayConfig& relay_config,
    std::span<const uint8_t> initial_payload,
    buf::MultiBuffer& first_payload,
    std::chrono::seconds relay_idle_timeout,
    std::chrono::seconds relay_write_timeout) {
    if (!inbound.Valid()) {
        co_return std::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }

    // UDP 数据面：dispatcher.Dispatch -> outbound.Process -> DoUDPRelayLink。
    // 不做 redirect（保持 UDP 逐包目标语义），首包/嗅探 payload 不适用于 UDP。
    if (ctx.content.network == Network::UDP) {
        if (!settings_.enable_udp) {
            co_return std::unexpected(ErrorCode::NOT_SUPPORTED);
        }
        UDPSession* session = nullptr;
        try {
            session = AcquireUdpSession(ctx);
        } catch (const std::exception& e) {
            LOG_CONN_FAIL_CTX(ctx, "UDP_DIAL_FAILED {} -> {} via {}: {}",
                              ctx.inbound.source_ip, ctx.outbound.target,
                              ctx.outbound.tag, e.what());
            co_return std::unexpected(ErrorCode::OUTBOUND_CONNECTION_FAILED);
        }
        if (!session) {
            LOG_CONN_FAIL_CTX(ctx, "UDP_DIAL_FAILED {} -> {} via {}",
                              ctx.inbound.source_ip, ctx.outbound.target,
                              ctx.outbound.tag);
            co_return std::unexpected(ErrorCode::OUTBOUND_CONNECTION_FAILED);
        }
        UDPRelayConfig udp_cfg;
        udp_cfg.speed_limit = ctx.content.speed_limit;
        co_return co_await DoUDPRelayLink(
            io_context, *inbound.reader, *inbound.writer, *session, ctx, stats, udp_cfg);
    }

    // redirect：替换目标地址（Xray freedom redirect 语义）
    if (redirect_target_) {
        LOG_CONN_DEBUG(ctx, "Freedom redirect {} -> {}",
                       ctx.outbound.target, redirect_target_text_);
        ctx.outbound.route_target = *redirect_target_;
        ctx.outbound.target = *redirect_target_;
    }

    const auto& target = ctx.outbound.target;
    if (!target.IsValid()) {
        co_return std::unexpected(ErrorCode::PROTOCOL_INVALID_ADDRESS);
    }

    LOG_CONN_DEBUG(ctx, "Freedom resolve target {}", target);

    OutboundTransportTarget transport_target;
    transport_target.bind_mode = bind_mode_;
    transport_target.timeout = dial_timeout_;
    transport_target.stream_settings = &stream_settings_;

    auto set_single_candidate = [&](const net::ip::address& remote_addr) {
        OutboundDialCandidate candidate;
        candidate.endpoint = tcp::endpoint(remote_addr, target.port);
        candidate.bind_local = DetermineLocalAddress(inbound_local_addr, remote_addr);
        transport_target.single_candidate = std::move(candidate);
    };

    if (target.IsIP() && target.resolved_addr) {
        ctx.content.dns_result = session::DnsResultState::None;
        set_single_candidate(*target.resolved_addr);
    } else {
        auto remote_addrs = co_await ResolveTargets(ctx);
        if (!remote_addrs || remote_addrs->empty()) {
            co_return std::unexpected(remote_addrs ? ErrorCode::DNS_RESOLVE_FAILED : remote_addrs.error());
        }

        if (remote_addrs->size() == 1) {
            set_single_candidate(remote_addrs->front());
        } else {
            transport_target.candidates.reserve(remote_addrs->size());
            for (const auto& remote_addr : *remote_addrs) {
                OutboundDialCandidate candidate;
                candidate.endpoint = tcp::endpoint(remote_addr, target.port);
                candidate.bind_local = DetermineLocalAddress(inbound_local_addr, remote_addr);
                transport_target.candidates.push_back(std::move(candidate));
            }
        }
    }

    if (transport_target.single_candidate) {
        const auto& candidate = *transport_target.single_candidate;
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
        LOG_CONN_DEBUG(ctx, "Freedom target {} resolved {} candidates",
                       target,
                       transport_target.candidates.size());
    }

    auto dial_result = co_await DialOutboundTransport(io_context, ctx, transport_target);
    if (!dial_result.Ok()) {
        LOG_CONN_FAIL_CTX(ctx, "DIAL_FAILED {} -> {} via {}: {}",
                          ctx.inbound.source_ip, ctx.outbound.target,
                          ctx.outbound.tag, dial_result.error_msg);
        co_return std::unexpected(dial_result.error);
    }

    auto stream = std::move(dial_result.stream);
    stream->SetStreamLabel("out");
    LOG_CONN_DEBUG(ctx, "[Outbound] TCP dial ok -> {} via {}",
                   ctx.outbound.target, ctx.outbound.tag);
    net::ip::address remote_ip{};
    net::ip::address local_ip{};
    if (auto remote_ep = stream->RemoteEndpoint()) {
        remote_ip = iputil::NormalizeAddress(remote_ep->address());
    }
    if (auto local_ep = stream->LocalEndpoint()) {
        local_ip = iputil::NormalizeAddress(local_ep->address());
    }
    LOG_ACCESS(FormatAccessLog(ctx, &remote_ip, &local_ip));

    stream->SetIdleTimeout(relay_idle_timeout);
    stream->SetReadTimeout(std::chrono::seconds(0));
    stream->SetWriteTimeout(relay_write_timeout);
    AsyncStream* inbound_control = inbound.control;

    if (buf::TotalLen(first_payload) > 0) {
        if (inbound_control) {
            co_return co_await DoRelayLinkWithFirstPacket(
                io_context, *inbound.reader, *inbound.writer, *inbound_control,
                *stream, ctx, stats, first_payload, relay_config);
        }
        co_return co_await DoRelayLinkWithFirstPacket(
            io_context, *inbound.reader, *inbound.writer, *stream, ctx, stats,
            first_payload, relay_config);
    }
    if (!initial_payload.empty()) {
        if (inbound_control) {
            co_return co_await DoRelayLinkWithFirstPacket(
                io_context, *inbound.reader, *inbound.writer, *inbound_control,
                *stream, ctx, stats, initial_payload, relay_config);
        }
        co_return co_await DoRelayLinkWithFirstPacket(
            io_context, *inbound.reader, *inbound.writer, *stream, ctx, stats,
            initial_payload, relay_config);
    }
    if (inbound_control) {
        co_return co_await DoRelayLink(
            io_context, *inbound.reader, *inbound.writer, *inbound_control,
            *stream, ctx, stats, relay_config);
    }
    co_return co_await DoRelayLink(
        io_context, *inbound.reader, *inbound.writer, *stream, ctx, stats, relay_config);
}

UDPSession* Handler::AcquireUdpSession(session::Context& ctx) {
    // Per-worker UDP session：同一 Worker 上同一出口 IP 共享一个 UDP socket。
    std::string bind_addr_storage;
    std::string session_id_storage;
    const std::string* bind_addr = nullptr;
    const std::string* session_id = nullptr;
    if (explicit_udp_bind_addr_ && explicit_udp_session_id_) {
        bind_addr = &*explicit_udp_bind_addr_;
        session_id = &*explicit_udp_session_id_;
    } else {
        bind_addr_storage = SelectUdpBindAddress(settings_, ctx);
        session_id_storage = MakeUdpSessionId(bind_addr_storage);
        bind_addr = &bind_addr_storage;
        session_id = &session_id_storage;
    }

    if (!udp_session_manager_) {
        LOG_CONN_FAIL("Freedom UDP: UDPSessionManager not available");
        return nullptr;
    }

    auto* session = udp_session_manager_->GetOrCreateSession(*session_id, *bind_addr);
    if (!session) {
        return nullptr;
    }

    LOG_CONN_DEBUG(ctx, "Freedom UDP session {} port {}", *session_id, session->LocalPort());
    return session;
}

net::awaitable<std::expected<std::vector<net::ip::address>, ErrorCode>>
Handler::ResolveTargets(session::Context& ctx) {
    const auto& target = ctx.outbound.target;

    // 如果目标已经有解析结果，直接复用 dispatcher/router 阶段的 DNS 结果。
    if (target.resolved_addr) {
        if (target.IsIP()) {
            ctx.content.dns_result = session::DnsResultState::None;
        }
        std::vector<net::ip::address> addresses;
        addresses.reserve(1);
        addresses.push_back(*target.resolved_addr);
        co_return addresses;
    }
    if (!target.IsDomain()) {
        co_return std::unexpected(ErrorCode::PROTOCOL_INVALID_ADDRESS);
    }

    // 需要 DNS 解析
    auto dns_result = co_await dns_service_.Resolve(target.host);

    if (!dns_result.Ok()) {
        ctx.content.dns_result = session::DnsResultState::Failed;
        co_return std::unexpected(ErrorCode::DNS_RESOLVE_FAILED);
    }

    std::vector<net::ip::address> addresses;
    addresses.reserve(dns_result.addresses.size());

    auto append_family = [&](const bool want_v6) {
        for (const auto& dns_addr : dns_result.addresses) {
            if (want_v6 ? dns_addr.is_v6() : dns_addr.is_v4()) {
                addresses.push_back(dns_addr);
            }
        }
    };

    if (PreservesDnsOrder(domain_strategy_)) {
        for (const auto& dns_addr : dns_result.addresses) {
            if ((dns_addr.is_v4() && AcceptsIPv4(domain_strategy_)) ||
                (dns_addr.is_v6() && AcceptsIPv6(domain_strategy_))) {
                addresses.push_back(dns_addr);
            }
        }
    } else if (PreferIPv6First(domain_strategy_)) {
        if (AcceptsIPv6(domain_strategy_)) {
            append_family(true);
        }
        if (AcceptsIPv4(domain_strategy_)) {
            append_family(false);
        }
    } else {
        if (AcceptsIPv4(domain_strategy_)) {
            append_family(false);
        }
        if (AcceptsIPv6(domain_strategy_)) {
            append_family(true);
        }
    }

    if (addresses.empty()) {
        ctx.content.dns_result = session::DnsResultState::Failed;
        co_return std::unexpected(ErrorCode::DNS_NO_RECORD);
    }

    ctx.content.dns_result = dns_result.from_cache
        ? session::DnsResultState::Cache
        : session::DnsResultState::Resolve;
    co_return addresses;
}

std::optional<net::ip::address> Handler::DetermineLocalAddress(
    const tcp::endpoint* inbound_local_addr,
    const net::ip::address& remote_addr) {

    if (bind_mode_ == OutboundTransportTarget::BindMode::Auto) {
        // auto 模式：源进源出
        // 使用入站连接的本地 IP 作为出站绑定地址
        // 这样可以实现「哪个 IP 进哪个 IP 出」

        if (!inbound_local_addr) {
            return std::nullopt;
        }
        auto inbound_local = iputil::NormalizeAddress(inbound_local_addr->address());
        if (!inbound_local.is_unspecified() && !inbound_local.is_loopback()) {
            if ((remote_addr.is_v4() && inbound_local.is_v4()) ||
                (remote_addr.is_v6() && inbound_local.is_v6())) {
                return inbound_local;
            }
        }
        return std::nullopt;
    }

    return explicit_send_through_addr_;
}

}  // namespace acpp::freedom::outbound

// ============================================================================
// 自注册（静态初始化，Xray init() 设计）
// ============================================================================
namespace {
const bool kFreedomRegistered = (acpp::proxyman::outbound::RegisterProxy(
    acpp::constants::protocol::kFreedom,
    [](const acpp::proxyman::outbound::OutboundSourceConfig& cfg)
        -> std::optional<acpp::proxyman::outbound::PreparedOutboundConfig> {
        const auto& s = cfg.settings;
        acpp::freedom::outbound::FreedomSettings settings;

        settings.send_through = std::string(acpp::constants::binding::kAuto);
        if (const auto* v = s.if_contains("sendThrough"); v && v->is_string()) {
            settings.send_through = std::string(v->as_string());
        }
        settings.domain_strategy = std::string(acpp::constants::protocol::kAsIs);
        if (const auto* v = s.if_contains("domainStrategy"); v && v->is_string()) {
            settings.domain_strategy = std::string(v->as_string());
        }
        if (const auto* v = s.if_contains("redirect"); v && v->is_string()) {
            settings.redirect = std::string(v->as_string());
        }

        // Xray 顶级 sendThrough 优先于 settings 内的
        if (!cfg.send_through.empty()) {
            settings.send_through = cfg.send_through;
        }

        acpp::proxyman::outbound::PreparedOutboundConfig prepared;
        prepared.tag = cfg.tag;
        prepared.protocol = cfg.protocol;
        prepared.create =
            [tag = cfg.tag, settings = std::move(settings)](
                acpp::net::io_context& /*io_context*/,
                acpp::app::dns::DNS& dns,
                acpp::UDPSessionManager* udp_mgr,
                std::chrono::seconds timeout) -> std::unique_ptr<acpp::Outbound> {
                return std::make_unique<acpp::freedom::outbound::Handler>(
                    tag, settings, dns, udp_mgr, timeout);
            };
        return prepared;
    }), true);
}  // namespace
