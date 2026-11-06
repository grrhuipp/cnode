#include "freedom_outbound.hpp"
#include "acppnode/app/dns/dns.hpp"
#include "acppnode/app/relay.hpp"
#include "acppnode/common/ip_utils.hpp"
#include "acppnode/common/session.hpp"
#include "acppnode/core/constants.hpp"
#include "acppnode/app/proxyman/outbound/factory.hpp"
#include "../../app/proxyman/outbound/registration.hpp"
#include "outbound/udp_request.hpp"
#include "acppnode/transport/internet/outbound_target_builder.hpp"
#include "acppnode/transport/internet/transport_dialer.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/infra/outbound_bind_config.hpp"

#include <algorithm>
#include <cctype>
#include <limits>

namespace acpp::proxy::freedom::outbound {

namespace {

std::optional<DomainStrategy> ParseConfiguredDomainStrategy(
    const json::object& settings) {
    const auto* value = settings.if_contains("domainStrategy");
    if (!value) return DomainStrategy::AsIs;
    if (!value->is_string()) return std::nullopt;
    return ParseDomainStrategy(value->as_string());
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

bool StrategyPrefersIPv6(DomainStrategy strategy) {
    switch (strategy) {
        case DomainStrategy::UseIPv6:
        case DomainStrategy::ForceIPv6:
        case DomainStrategy::UseIPv6v4:
        case DomainStrategy::ForceIPv6v4:
            return true;
        default:
            return false;
    }
}

net::ip::address SelectUdpBindAddress(
    const OutboundBind& send_through,
    DomainStrategy domain_strategy,
    const tcp::endpoint* inbound_local_addr,
    const session::Context& ctx) {
    const bool auto_bind = send_through.GetMode() == OutboundBind::Mode::Auto;
    if (send_through.GetMode() == OutboundBind::Mode::Explicit) {
        return *send_through.ExplicitAddress();
    }

    const auto& target = ctx.outbound.target;
    const tcp::endpoint* local_ep = inbound_local_addr
        ? inbound_local_addr
        : (ctx.inbound.local_endpoint ? &*ctx.inbound.local_endpoint : nullptr);
    const bool target_is_v6 =
        target.type == AddressType::IPv6 ||
        (target.type != AddressType::Domain &&
         target.resolved_addr && target.resolved_addr->is_v6());
    const bool target_is_v4 =
        target.type == AddressType::IPv4 ||
        (target.type != AddressType::Domain &&
         target.resolved_addr && target.resolved_addr->is_v4());

    if (auto_bind && local_ep) {
        const auto inbound_local =
            iputil::NormalizeAddress(local_ep->address());
        const bool strategy_allows_local =
            (target_is_v4 || target_is_v6) ||
            (inbound_local.is_v6() ? AcceptsIPv6(domain_strategy)
                                   : AcceptsIPv4(domain_strategy));
        if (!inbound_local.is_unspecified() && !inbound_local.is_loopback() &&
            strategy_allows_local &&
            ((target_is_v4 && inbound_local.is_v4()) ||
             (target_is_v6 && inbound_local.is_v6()) ||
             (!target_is_v4 && !target_is_v6))) {
            return inbound_local;
        }
    }

    if (target_is_v6) {
        return net::ip::address_v6::any();
    }
    if (target_is_v4) {
        return net::ip::address_v4::any();
    }
    if (StrategyPrefersIPv6(domain_strategy)) {
        return net::ip::address_v6::any();
    }
    if (!AcceptsIPv6(domain_strategy)) {
        return net::ip::address_v4::any();
    }
    if (target.resolved_addr) {
        return target.resolved_addr->is_v6()
            ? net::ip::address(net::ip::address_v6::any())
            : net::ip::address(net::ip::address_v4::any());
    }
    if (send_through.PrefersIPv6()) {
        return net::ip::address_v6::any();
    }
    return net::ip::address_v4::any();
}

}  // namespace

Handler::Handler(
    std::string_view tag,
    const FreedomSettings& settings,
    ::acpp::app::dns::DNS& dns_service,
    std::chrono::seconds dial_timeout)
    : tag_(tag)
    , send_through_(settings.send_through)
    , domain_strategy_(settings.domain_strategy)
    , dns_service_(dns_service)
    , dial_timeout_(dial_timeout)
    , redirect_target_(settings.redirect) {}

net::awaitable<OutboundProcessResult> Handler::Process(
    net::io_context& io_context,
    const tcp::endpoint* inbound_local_addr,
    session::Context& ctx,
    const TimeoutsConfig& /*timeouts*/,
    transport::Link inbound,
    StatsShard& stats,
    const RelayConfig& relay_config,
    buf::MultiBufferBatch first_payload,
    std::chrono::seconds relay_idle_timeout,
    std::chrono::seconds relay_write_timeout) {
    if (!inbound.Valid()) {
        co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }

    // UDP 数据面：dispatcher.Dispatch -> outbound.Process -> DoRelayLink。
    // 不做 redirect（保持 UDP 逐包目标语义）；嗅探首包作为普通上行交给转发。
    if (ctx.content.network == Network::UDP) {
        auto bind_address = SelectUdpBindAddress(
            send_through_, domain_strategy_, inbound_local_addr, ctx);
        if (send_through_.GetMode() == OutboundBind::Mode::Ordered) {
            auto selected = send_through_.Select(
                bind_address, ctx.inbound.source_ip, ctx.inbound.source_port);
            if (!selected.address && ctx.outbound.target.IsDomain()) {
                const bool allow_alt = bind_address.is_v6()
                    ? AcceptsIPv4(domain_strategy_)
                    : AcceptsIPv6(domain_strategy_);
                if (allow_alt) {
                    const net::ip::address alt_family = bind_address.is_v6()
                        ? net::ip::address(net::ip::address_v4::any())
                        : net::ip::address(net::ip::address_v6::any());
                    selected = send_through_.Select(
                        alt_family, ctx.inbound.source_ip, ctx.inbound.source_port);
                }
            }
            if (!selected.address) {
                co_return tl::unexpected(ErrorCode::SOCKET_BIND_FAILED);
            }
            bind_address = *selected.address;
        }
        std::optional<UdpRequest> target;
        try {
            target.emplace(io_context, dns_service_, bind_address);
        } catch (const transport::LinkError& e) {
            LOG_CONN_DEBUG(ctx, "failed to dial UDP {} via {} > {}",
                           ctx.outbound.target, iputil::AddressText(bind_address).View(), e.what());
            co_return tl::unexpected(e.code());
        } catch (const IoSystemError& e) {
            LOG_CONN_DEBUG(ctx, "failed to dial UDP {} via {} > {}",
                           ctx.outbound.target, iputil::AddressText(bind_address).View(), e.what());
            co_return tl::unexpected(MapAsioError(e.code()));
        }
        ctx.outbound.connected_local_addr.reset();
        const auto local_ip = iputil::NormalizeAddress(bind_address);
        if (!local_ip.is_unspecified()) {
            ctx.outbound.connected_local_addr = local_ip;
        }
        LOG_ACCESS(FormatAccessLog(ctx));
        target->SetIdleTimeout(relay_idle_timeout);
        target->SetWriteTimeout(relay_write_timeout);
        co_return co_await DoRelayLink(io_context, *inbound.reader, *inbound.writer,
            inbound.control, *target, ctx, stats, relay_config, std::move(first_payload));
    }

    // redirect：替换目标地址（Xray freedom redirect 语义）
    if (redirect_target_) {
        LOG_CONN_DEBUG(ctx, "redirect {} -> {}",
                       ctx.outbound.target, *redirect_target_);
        ctx.outbound.route_target = *redirect_target_;
        ctx.outbound.target = *redirect_target_;
    }

    auto dialed = co_await DialOutboundStream(io_context, inbound_local_addr, ctx);
    if (!dialed) {
        co_return tl::unexpected(dialed.error());
    }
    auto stream = std::move(*dialed);
    stream->SetIdleTimeout(relay_idle_timeout);
    stream->SetReadTimeout(std::chrono::seconds(0));
    stream->SetWriteTimeout(relay_write_timeout);
    co_return co_await DoRelayLink(
        io_context, *inbound.reader, *inbound.writer, inbound.control,
        *stream, ctx, stats, relay_config, std::move(first_payload));
}

net::awaitable<tl::expected<std::unique_ptr<AsyncStream>, ErrorCode>>
Handler::DialOutboundStream(
    net::io_context& io_context,
    const tcp::endpoint* inbound_local_addr,
    session::Context& ctx) {
    const auto& target = ctx.outbound.target;
    if (!target.IsValid()) {
        co_return tl::unexpected(ErrorCode::PROTOCOL_INVALID_ADDRESS);
    }

    LOG_CONN_DEBUG(ctx, "resolving target {}", target);

    OutboundTransportTarget transport_target;
    transport_target.timeout = dial_timeout_;
    transport_target.stream_settings = &stream_settings_;

    const bool ordered_bind = send_through_.GetMode() == OutboundBind::Mode::Ordered;
    const auto selected_v4 = ordered_bind
        ? send_through_.Select(net::ip::address_v4::any(),
            ctx.inbound.source_ip, ctx.inbound.source_port)
        : OutboundBind::Selection{};
    const auto selected_v6 = ordered_bind
        ? send_through_.Select(net::ip::address_v6::any(),
            ctx.inbound.source_ip, ctx.inbound.source_port)
        : OutboundBind::Selection{};
    auto selected_bind = [&](const net::ip::address& remote_addr)
        -> std::optional<net::ip::address> {
        return ordered_bind
            ? (remote_addr.is_v6() ? selected_v6.address : selected_v4.address)
            : send_through_.BindAddressFor(inbound_local_addr, remote_addr);
    };
    auto set_single_candidate = [&](const net::ip::address& remote_addr) {
        OutboundDialCandidate candidate;
        candidate.endpoint = tcp::endpoint(remote_addr, target.port);
        candidate.bind_local = selected_bind(remote_addr);
        transport_target.single_candidate = std::move(candidate);
    };

    if (target.IsIP() && target.resolved_addr &&
        domain_strategy_ != DomainStrategy::ForceIPv4 &&
        domain_strategy_ != DomainStrategy::ForceIPv6) {
        set_single_candidate(*target.resolved_addr);
    } else {
        auto remote_addrs = co_await ResolveTargets(ctx);
        if (!remote_addrs || remote_addrs->empty()) {
            co_return tl::unexpected(remote_addrs ? ErrorCode::DNS_RESOLVE_FAILED : remote_addrs.error());
        }

        transport_target.candidates.reserve(remote_addrs->size());
        for (const auto& remote_addr : *remote_addrs) {
            transport_target.candidates.push_back(OutboundDialCandidate{
                .endpoint = tcp::endpoint(remote_addr, target.port),
                .bind_local = selected_bind(remote_addr),
            });
        }
        if (transport_target.candidates.empty()) {
            co_return tl::unexpected(ErrorCode::SOCKET_BIND_FAILED);
        }
        if (transport_target.candidates.size() == 1) {
            transport_target.single_candidate = std::move(transport_target.candidates.front());
            transport_target.candidates.clear();
        }
    }

    if (transport_target.single_candidate) {
        const auto& candidate = *transport_target.single_candidate;
        if (candidate.bind_local) {
            LOG_CONN_DEBUG(ctx, "target {}:{} bind {}",
                           iputil::AddressText(candidate.endpoint.address()).View(),
                           candidate.endpoint.port(),
                           iputil::AddressText(*candidate.bind_local).View());
        } else {
            LOG_CONN_DEBUG(ctx, "target {}:{} (system bind)",
                           iputil::AddressText(candidate.endpoint.address()).View(),
                           candidate.endpoint.port());
        }
    } else {
        LOG_CONN_DEBUG(ctx, "target {} resolved {} candidates",
                       target,
                       transport_target.candidates.size());
    }

    ctx.outbound.connected_local_addr.reset();
    auto dial_result = co_await DialOutboundTransport(io_context, ctx, transport_target);
    if (!dial_result.Ok()) {
        LOG_CONN_DEBUG(ctx, "failed to dial {} -> {} > {}",
                       ctx.inbound.source_ip, ctx.outbound.target, dial_result.error_msg);
        co_return tl::unexpected(dial_result.error);
    }

    auto stream = std::move(dial_result.stream);
    LOG_CONN_DEBUG(ctx, "TCP dial succeeded -> {}", ctx.outbound.target);
    RecordOutboundStreamConnected(ctx, *stream);
    co_return std::move(stream);
}

net::awaitable<tl::expected<memory::ThreadLocalVector<net::ip::address>, ErrorCode>>
Handler::ResolveTargets(session::Context& ctx) {
    const auto& target = ctx.outbound.target;

    if (!target.IsDomain()) {
        if (!target.resolved_addr) {
            co_return tl::unexpected(ErrorCode::PROTOCOL_INVALID_ADDRESS);
        }
        if ((domain_strategy_ == DomainStrategy::ForceIPv4 ||
             domain_strategy_ == DomainStrategy::ForceIPv6) &&
            !(target.resolved_addr->is_v6()
                ? AcceptsIPv6(domain_strategy_)
                : AcceptsIPv4(domain_strategy_))) {
            co_return tl::unexpected(ErrorCode::DNS_NO_RECORD);
        }
        memory::ThreadLocalVector<net::ip::address> addresses;
        addresses.reserve(1);
        addresses.push_back(*target.resolved_addr);
        co_return addresses;
    }

    // 需要 DNS 解析
    auto dns_result = co_await dns_service_.Resolve(target.host);

    if (!dns_result.Ok()) {
        co_return tl::unexpected(ErrorCode::DNS_RESOLVE_FAILED);
    }

    memory::ThreadLocalVector<net::ip::address> addresses;
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
        co_return tl::unexpected(ErrorCode::DNS_NO_RECORD);
    }

    co_return addresses;
}

proxyman::outbound::PreparedOutboundCreator PrepareOutbound(FreedomSettings settings) {
    return proxyman::outbound::MakePreparedOutboundCreator<
        FreedomSettings,
        +[](std::string_view tag, std::shared_ptr<const FreedomSettings> config,
            net::io_context&, app::dns::DNS& dns,
            std::chrono::seconds timeout, AwaitableTaskGroup&) -> std::unique_ptr<Outbound> {
            return std::make_unique<Handler>(tag, *config, dns, timeout);
        }>(std::move(settings));
}

}  // namespace acpp::proxy::freedom::outbound

// ============================================================================
// 自注册（静态初始化，Xray init() 设计）
// ============================================================================
namespace {
const bool kFreedomRegistered = (acpp::proxyman::outbound::RegisterProxy(
    acpp::constants::protocol::kFreedom,
    [](const acpp::infra::OutboundSourceConfig& cfg)
        -> std::optional<acpp::proxyman::outbound::PreparedOutboundCreator> {
        const auto& s = cfg.settings;
        acpp::proxy::freedom::outbound::FreedomSettings settings;

        settings.send_through = acpp::OutboundBind::Auto();
        if (s.contains("send_through")) return std::nullopt;
        const auto* nested_send_through = s.if_contains("sendThrough");
        const auto* nested_strategy = s.if_contains("sendThroughStrategy");
        if (nested_strategy && !nested_send_through) return std::nullopt;
        if (nested_send_through) {
            try {
                settings.send_through = acpp::infra::ParseOutboundBindConfig(
                    *nested_send_through, nested_strategy);
            } catch (const std::invalid_argument&) {
                return std::nullopt;
            }
        }
        const auto domain_strategy =
            acpp::proxy::freedom::outbound::ParseConfiguredDomainStrategy(s);
        if (!domain_strategy) {
            return std::nullopt;
        }
        settings.domain_strategy = *domain_strategy;
        // 空字符串与缺省同义（Xray 示例配置写法），其他值必须是合法的 host:port。
        if (const auto* v = s.if_contains("redirect");
            v && !(v->is_string() && v->as_string().empty())) {
            auto redirect = v->is_string()
                ? acpp::TargetAddress::Parse(v->as_string())
                : std::nullopt;
            if (!redirect || !redirect->IsValid()) {
                LOG_ERROR("freedom outbound '{}': redirect must be a valid host:port", cfg.tag);
                return std::nullopt;
            }
            settings.redirect = std::move(*redirect);
        }

        // Xray 顶级 sendThrough 优先于 settings 内的
        if (cfg.send_through) {
            settings.send_through = *cfg.send_through;
        }

        return acpp::proxy::freedom::outbound::PrepareOutbound(std::move(settings));
    }), true);
}  // namespace
