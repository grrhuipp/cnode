#include "freedom_outbound.hpp"
#include "acppnode/app/dns/dns.hpp"
#include "acppnode/app/relay.hpp"
#include "acppnode/common/ip_utils.hpp"
#include "acppnode/common/session.hpp"
#include "acppnode/core/constants.hpp"
#include "acppnode/app/proxyman/outbound/factory.hpp"
#include "../../app/proxyman/outbound/source_config.hpp"
#include "acppnode/app/udp_session.hpp"
#include "acppnode/transport/internet/transport_dialer.hpp"
#include "acppnode/infra/log.hpp"

#include <cctype>

namespace acpp::proxy::freedom::outbound {

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

std::optional<DomainStrategy> ParseDomainStrategy(std::string_view value) {
    const auto lower = LowerAscii(value);
    if (lower == "asis") {
        return DomainStrategy::AsIs;
    }
    if (lower == "useip") {
        return DomainStrategy::UseIP;
    }
    if (lower == "useipv6v4") {
        return DomainStrategy::UseIPv6v4;
    }
    if (lower == "useipv6") {
        return DomainStrategy::UseIPv6;
    }
    if (lower == "useipv4v6") {
        return DomainStrategy::UseIPv4v6;
    }
    if (lower == "useipv4") {
        return DomainStrategy::UseIPv4;
    }
    if (lower == "forceip") {
        return DomainStrategy::ForceIP;
    }
    if (lower == "forceipv6v4") {
        return DomainStrategy::ForceIPv6v4;
    }
    if (lower == "forceipv6") {
        return DomainStrategy::ForceIPv6;
    }
    if (lower == "forceipv4v6") {
        return DomainStrategy::ForceIPv4v6;
    }
    if (lower == "forceipv4") {
        return DomainStrategy::ForceIPv4;
    }
    return std::nullopt;
}

std::optional<DomainStrategy> ParseConfiguredDomainStrategy(
    const json::object& settings) {
    DomainStrategy parsed = DomainStrategy::AsIs;
    bool present = false;
    for (const std::string_view key : {"domainStrategy", "domain_strategy"}) {
        const auto* value = settings.if_contains(key);
        if (!value || !value->is_string()) {
            if (value) return std::nullopt;
            continue;
        }
        const auto candidate = ParseDomainStrategy(value->as_string());
        if (!candidate || (present && parsed != *candidate)) {
            return std::nullopt;
        }
        parsed = *candidate;
        present = true;
    }
    return parsed;
}

bool AcceptsIPv4(DomainStrategy strategy) {
    switch (strategy) {
        case DomainStrategy::UseIPv6:
        case DomainStrategy::ForceIPv6:
            return false;
        default:
            return true;
    }
}

bool AcceptsIPv6(DomainStrategy strategy) {
    switch (strategy) {
        case DomainStrategy::UseIPv4:
        case DomainStrategy::ForceIPv4:
            return false;
        default:
            return true;
    }
}

bool PreferIPv6First(DomainStrategy strategy) {
    switch (strategy) {
        case DomainStrategy::UseIPv6v4:
        case DomainStrategy::ForceIPv6v4:
            return true;
        default:
            return false;
    }
}

bool PreservesDnsOrder(DomainStrategy strategy) {
    switch (strategy) {
        case DomainStrategy::AsIs:
        case DomainStrategy::UseIP:
        case DomainStrategy::ForceIP:
            return true;
        default:
            return false;
    }
}

net::ip::address SelectUdpBindAddress(
    const FreedomSettings& settings,
    const session::Context& ctx) {
    const bool auto_bind = settings.send_through.GetMode() == OutboundBind::Mode::Auto;
    if (settings.send_through.GetMode() == OutboundBind::Mode::Explicit) {
        return *settings.send_through.ExplicitAddress();
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
            return inbound_local;
        }
    }

    if ((target.resolved_addr && target.resolved_addr->is_v6()) ||
        target.type == AddressType::IPv6) {
        return net::ip::address_v6::any();
    }

    return net::ip::address_v4::any();
}

std::string MakeUdpSessionId(const net::ip::address& bind_addr) {
    const auto text = bind_addr.to_string();
    std::string session_id;
    session_id.reserve(4 + text.size());
    session_id.append("udp-");
    session_id.append(text);
    return session_id;
}

OutboundTransportTarget::BindMode ToTransportBindMode(OutboundBind::Mode mode) {
    switch (mode) {
        case OutboundBind::Mode::None:
            return OutboundTransportTarget::BindMode::None;
        case OutboundBind::Mode::Auto:
            return OutboundTransportTarget::BindMode::Auto;
        case OutboundBind::Mode::Explicit:
            return OutboundTransportTarget::BindMode::Explicit;
    }
    return OutboundTransportTarget::BindMode::None;
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

    if (settings_.send_through.GetMode() == OutboundBind::Mode::Explicit) {
        explicit_udp_session_id_ =
            MakeUdpSessionId(*settings_.send_through.ExplicitAddress());
    }

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
        std::expected<std::shared_ptr<UDPSession>, ErrorCode> session_result;
        try {
            session_result = AcquireUdpSession(ctx);
        } catch (const std::exception& e) {
            LOG_CONN_FAIL_CTX(ctx, "UDP_DIAL_FAILED {} -> {} via {}: {}",
                              ctx.inbound.source_ip, ctx.outbound.target,
                              ctx.outbound.tag, e.what());
            co_return std::unexpected(ErrorCode::OUTBOUND_CONNECTION_FAILED);
        }
        if (!session_result) {
            LOG_CONN_FAIL_CTX(ctx, "UDP_DIAL_FAILED {} -> {} via {}",
                              ctx.inbound.source_ip, ctx.outbound.target,
                              ctx.outbound.tag);
            co_return std::unexpected(session_result.error());
        }
        std::shared_ptr<UDPSession> session = std::move(*session_result);
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
    transport_target.bind_mode = ToTransportBindMode(settings_.send_through.GetMode());
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

    ctx.outbound.connected_target_addr.reset();
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
        if (!remote_ip.is_unspecified()) {
            ctx.outbound.connected_target_addr = remote_ip;
        }
    }
    if (auto local_ep = stream->LocalEndpoint()) {
        local_ip = iputil::NormalizeAddress(local_ep->address());
    }
    LOG_ACCESS(FormatAccessLog(ctx, &remote_ip, &local_ip));

    stream->SetIdleTimeout(relay_idle_timeout);
    stream->SetReadTimeout(std::chrono::seconds(0));
    stream->SetWriteTimeout(relay_write_timeout);
    AsyncStream* inbound_control = inbound.control;

    if (buf::HasData(first_payload)) {
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

std::expected<std::shared_ptr<UDPSession>, ErrorCode>
Handler::AcquireUdpSession(session::Context& ctx) {
    // Per-worker UDP session：同一 Worker 上同一出口 IP 共享一个 UDP socket。
    net::ip::address bind_addr_storage;
    std::string session_id_storage;
    const net::ip::address* bind_addr = nullptr;
    const std::string* session_id = nullptr;
    if (settings_.send_through.GetMode() == OutboundBind::Mode::Explicit &&
        explicit_udp_session_id_) {
        bind_addr = &*settings_.send_through.ExplicitAddress();
        session_id = &*explicit_udp_session_id_;
    } else {
        bind_addr_storage = SelectUdpBindAddress(settings_, ctx);
        session_id_storage = MakeUdpSessionId(bind_addr_storage);
        bind_addr = &bind_addr_storage;
        session_id = &session_id_storage;
    }

    if (!udp_session_manager_) {
        LOG_CONN_FAIL("Freedom UDP: UDPSessionManager not available");
        return std::unexpected(ErrorCode::OUTBOUND_CONNECTION_FAILED);
    }

    auto session = udp_session_manager_->AcquireSession(*session_id, *bind_addr);
    if (!session) {
        return std::unexpected(session.error());
    }

    LOG_CONN_DEBUG(ctx, "Freedom UDP session {} port {}", *session_id, (*session)->LocalPort());
    return *session;
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

    if (PreservesDnsOrder(settings_.domain_strategy)) {
        for (const auto& dns_addr : dns_result.addresses) {
            if ((dns_addr.is_v4() && AcceptsIPv4(settings_.domain_strategy)) ||
                (dns_addr.is_v6() && AcceptsIPv6(settings_.domain_strategy))) {
                addresses.push_back(dns_addr);
            }
        }
    } else if (PreferIPv6First(settings_.domain_strategy)) {
        if (AcceptsIPv6(settings_.domain_strategy)) {
            append_family(true);
        }
        if (AcceptsIPv4(settings_.domain_strategy)) {
            append_family(false);
        }
    } else {
        if (AcceptsIPv4(settings_.domain_strategy)) {
            append_family(false);
        }
        if (AcceptsIPv6(settings_.domain_strategy)) {
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

    if (settings_.send_through.GetMode() == OutboundBind::Mode::Auto) {
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

    return settings_.send_through.ExplicitAddress();
}

}  // namespace acpp::proxy::freedom::outbound

// ============================================================================
// 自注册（静态初始化，Xray init() 设计）
// ============================================================================
namespace {
const bool kFreedomRegistered = (acpp::proxyman::outbound::RegisterProxy(
    acpp::constants::protocol::kFreedom,
    [](const acpp::proxyman::outbound::OutboundSourceConfig& cfg)
        -> std::optional<acpp::proxyman::outbound::PreparedOutboundCreator> {
        const auto& s = cfg.settings;
        acpp::proxy::freedom::outbound::FreedomSettings settings;

        settings.send_through = acpp::OutboundBind::Auto();
        const acpp::json::value* nested_send_through = s.if_contains("sendThrough");
        if (!nested_send_through) {
            nested_send_through = s.if_contains("send_through");
        }
        if (nested_send_through) {
            if (!nested_send_through->is_string()) {
                return std::nullopt;
            }
            auto parsed = acpp::OutboundBind::Parse(nested_send_through->as_string());
            if (!parsed) {
                return std::nullopt;
            }
            settings.send_through = std::move(*parsed);
        }
        const auto domain_strategy =
            acpp::proxy::freedom::outbound::ParseConfiguredDomainStrategy(s);
        if (!domain_strategy) {
            return std::nullopt;
        }
        settings.domain_strategy = *domain_strategy;
        if (const auto* v = s.if_contains("redirect"); v && v->is_string()) {
            settings.redirect = std::string(v->as_string());
        }

        // Xray 顶级 sendThrough 优先于 settings 内的
        if (cfg.send_through) {
            settings.send_through = *cfg.send_through;
        }

        return acpp::proxyman::outbound::PreparedOutboundCreator{
            [settings = std::move(settings)](
                std::string_view tag,
                acpp::net::io_context& /*io_context*/,
                acpp::app::dns::DNS& dns,
                acpp::UDPSessionManager* udp_mgr,
                std::chrono::seconds timeout) -> std::unique_ptr<acpp::Outbound> {
                return std::make_unique<acpp::proxy::freedom::outbound::Handler>(
                    std::string(tag), settings, dns, udp_mgr, timeout);
            }};
    }), true);
}  // namespace
