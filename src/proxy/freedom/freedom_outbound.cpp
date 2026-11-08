#include "freedom_outbound.hpp"
#include "app/dns/dns.hpp"
#include "app/relay.hpp"
#include "common/ip_utils.hpp"
#include "common/session.hpp"
#include "core/constants.hpp"
#include "app/proxyman/outbound/factory.hpp"
#include "../../app/proxyman/outbound/registration.hpp"
#include "outbound/udp_request.hpp"
#include "transport/internet/outbound_target_builder.hpp"
#include "transport/internet/transport_dialer.hpp"
#include "infra/log.hpp"
#include "infra/outbound_bind_config.hpp"

#include <algorithm>
#include <cctype>
#include <limits>

namespace proxy::freedom::outbound {

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

}  // namespace

Handler::Handler(const FreedomSettings& settings)
    : domain_strategy_(settings.domain_strategy)
    , redirect_target_(settings.redirect) {}

net::awaitable<OutboundProcessResult> Handler::Process(
    session::Context& ctx,
    transport::Link inbound,
    OutboundDialer& dialer,
    const TimeoutsConfig& /*timeouts*/,
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
        const auto& target = ctx.outbound.target;
        std::optional<UdpRequest> endpoint;
        if (auto opened = dialer.OpenDatagram(ctx, OutboundDialer::DatagramRemote{
                .address = target.IsDomain() ? std::nullopt : target.resolved_addr,
                .family_hint = target.IsDomain() ? target.resolved_addr : std::nullopt,
                .accepts_v4 = AcceptsIPv4(domain_strategy_),
                .accepts_v6 = AcceptsIPv6(domain_strategy_),
                .prefers_v6 = StrategyPrefersIPv6(domain_strategy_),
            }, endpoint); !opened) {
            co_return tl::unexpected(opened.error());
        }
        endpoint->SetIdleTimeout(relay_idle_timeout);
        endpoint->SetWriteTimeout(relay_write_timeout);
        co_return co_await DoRelayLink(dialer.IoContext(), *inbound.reader, *inbound.writer,
            inbound.control, *endpoint, ctx, stats, relay_config, std::move(first_payload));
    }

    // redirect：替换目标地址（Xray freedom redirect 语义）
    if (redirect_target_) {
        LOG_CONN_DEBUG(ctx, "redirect {} -> {}",
                       ctx.outbound.target, *redirect_target_);
        ctx.outbound.route_target = *redirect_target_;
        ctx.outbound.target = *redirect_target_;
    }

    auto dialed = co_await DialTarget(dialer, ctx);
    if (!dialed) {
        co_return tl::unexpected(dialed.error());
    }
    auto stream = std::move(*dialed);
    stream->SetIdleTimeout(relay_idle_timeout);
    stream->SetReadTimeout(std::chrono::seconds(0));
    stream->SetWriteTimeout(relay_write_timeout);
    co_return co_await DoRelayLink(
        dialer.IoContext(), *inbound.reader, *inbound.writer, inbound.control,
        *stream, ctx, stats, relay_config, std::move(first_payload));
}

net::awaitable<tl::expected<std::unique_ptr<AsyncStream>, ErrorCode>>
Handler::DialTarget(OutboundDialer& dialer, session::Context& ctx) {
    const auto& target = ctx.outbound.target;
    if (!target.IsValid()) {
        co_return tl::unexpected(ErrorCode::PROTOCOL_INVALID_ADDRESS);
    }

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
        const net::ip::address address = *target.resolved_addr;
        co_return co_await dialer.Dial(
            ctx, std::span<const net::ip::address>(&address, 1), target.port);
    }

    LOG_CONN_DEBUG(ctx, "resolving target {}", target);
    auto addresses = co_await ResolveTargets(dialer.Dns(), ctx);
    if (!addresses || addresses->empty()) {
        co_return tl::unexpected(addresses ? ErrorCode::DNS_RESOLVE_FAILED : addresses.error());
    }
    co_return co_await dialer.Dial(
        ctx, std::span<const net::ip::address>(addresses->data(), addresses->size()),
        target.port);
}

net::awaitable<tl::expected<memory::ThreadLocalVector<net::ip::address>, ErrorCode>>
Handler::ResolveTargets(::app::dns::DNS& dns, session::Context& ctx) {
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
    auto dns_result = co_await dns.Resolve(target.host);

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
        +[](std::string_view, std::shared_ptr<const FreedomSettings> config,
            net::io_context&, AwaitableTaskGroup&) -> std::unique_ptr<Outbound> {
            return std::make_unique<Handler>(*config);
        }>(std::move(settings));
}

}  // namespace proxy::freedom::outbound

// ============================================================================
// 自注册（静态初始化，Xray init() 设计）
// ============================================================================
namespace {
const bool kFreedomRegistered = (::proxyman::outbound::RegisterProxy(
    ::constants::protocol::kFreedom,
    [](const ::infra::OutboundSourceConfig& cfg)
        -> std::optional<::proxyman::outbound::PreparedOutboundProxy> {
        const auto& s = cfg.settings;
        ::proxy::freedom::outbound::FreedomSettings settings;
        // Freedom keeps the default raw TCP stream; its sendThrough defaults
        // to same-in-same-out. A top-level sendThrough overrides this nested one.
        ::OutboundSenderSettings sender{.stream_settings = {},
                                            .send_through = ::OutboundBind::Auto()};

        if (s.contains("send_through")) return std::nullopt;
        const auto* nested_send_through = s.if_contains("sendThrough");
        const auto* nested_strategy = s.if_contains("sendThroughStrategy");
        if (nested_strategy && !nested_send_through) return std::nullopt;
        if (nested_send_through) {
            try {
                sender.send_through = ::infra::ParseOutboundBindConfig(
                    *nested_send_through, nested_strategy);
            } catch (const std::invalid_argument&) {
                return std::nullopt;
            }
        }
        const auto domain_strategy =
            ::proxy::freedom::outbound::ParseConfiguredDomainStrategy(s);
        if (!domain_strategy) {
            return std::nullopt;
        }
        settings.domain_strategy = *domain_strategy;
        // 空字符串与缺省同义（Xray 示例配置写法），其他值必须是合法的 host:port。
        if (const auto* v = s.if_contains("redirect");
            v && !(v->is_string() && v->as_string().empty())) {
            auto redirect = v->is_string()
                ? ::TargetAddress::Parse(v->as_string())
                : std::nullopt;
            if (!redirect || !redirect->IsValid()) {
                LOG_ERROR("freedom outbound '{}': redirect must be a valid host:port", cfg.tag);
                return std::nullopt;
            }
            settings.redirect = std::move(*redirect);
        }

        return ::proxyman::outbound::PreparedOutboundProxy{
            .create = ::proxy::freedom::outbound::PrepareOutbound(std::move(settings)),
            .sender = std::move(sender),
        };
    }), true);
}  // namespace
