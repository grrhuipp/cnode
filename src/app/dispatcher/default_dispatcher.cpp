#include "acppnode/app/dispatcher/default_dispatcher.hpp"

#include "acppnode/app/session_tracking.hpp"
#include "acppnode/app/dns/dns.hpp"
#include "acppnode/app/proxyman/inbound/receiver_settings.hpp"
#include "acppnode/common/ip_utils.hpp"
#include "acppnode/common/rule.hpp"
#include "acppnode/common/session.hpp"
#include "acppnode/features/outbound/outbound.hpp"
#include "acppnode/infra/config_types.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/proxy/inbound.hpp"
#include "acppnode/app/router/router.hpp"
#include "acppnode/common/mux/mux_relay.hpp"
#include "acppnode/sniff/sniffer.hpp"
#include "acppnode/transport/link.hpp"
#include "acppnode/common/buf/multi_buffer.hpp"

#include <algorithm>
#include <cstring>
#include <vector>

namespace acpp::app::dispatcher {

namespace {

[[nodiscard]] RelayResult MakeRelayError(ErrorCode error) noexcept {
    RelayResult result;
    result.error = error;
    return result;
}

std::chrono::seconds ResolveRelayIdleTimeout(
    const TimeoutsConfig& timeouts,
    uint32_t pressure_idle_timeout) {
    auto idle_timeout = timeouts.StreamIdleTimeout();
    if (pressure_idle_timeout > 0) {
        idle_timeout = std::min(
            idle_timeout, std::chrono::seconds(pressure_idle_timeout));
    }
    return idle_timeout;
}

net::awaitable<std::vector<net::ip::address>> ResolveRoutingAddresses(
    app::dns::DNS& dns_service,
    session::Context& ctx) {
    const auto& target = ctx.outbound.target;
    if (target.resolved_addr) {
        co_return std::vector<net::ip::address>{*target.resolved_addr};
    }
    if (!target.IsDomain()) {
        co_return std::vector<net::ip::address>{};
    }

    auto dns_result = co_await dns_service.Resolve(target.host);
    if (!dns_result.Ok()) {
        ctx.content.dns_result = session::DnsResultState::Failed;
        LOG_CONN_DEBUG(ctx, "[Dispatcher] route DNS resolve failed for {}", target.host);
        co_return std::vector<net::ip::address>{};
    }

    ctx.content.dns_result = dns_result.from_cache
        ? session::DnsResultState::Cache
        : session::DnsResultState::Resolve;
    co_return std::move(dns_result.addresses);
}

struct ActiveSessionScope {
    session::Context& ctx;
    app::SessionTrackingState* session_tracking = nullptr;
    bool is_active = false;

    ActiveSessionScope(session::Context& session_ctx,
                       app::SessionTrackingState* tracking)
        : ctx(session_ctx)
        , session_tracking(tracking) {
        if (session_tracking && ctx.inbound.user_id > 0) {
            session_tracking->RegisterActiveSession(
                ctx.conn_id,
                ctx.inbound.tag,
                ctx.inbound.user_id,
                ctx.traffic);
            is_active = true;
        }
    }

    ~ActiveSessionScope() noexcept {
        if (!is_active || !session_tracking) {
            return;
        }

        session_tracking->UnregisterActiveSession(
            ctx.conn_id,
            ctx.traffic);
    }
};

}  // namespace

DefaultDispatcher::DefaultDispatcher(app::router::Router& router) noexcept
    : router_(&router) {}

void DefaultDispatcher::BindRouter(app::router::Router& router) noexcept {
    router_ = &router;
}

void DefaultDispatcher::BindOutboundManager(
    features::outbound::Manager& outbound_manager) noexcept {
    outbound_manager_ = &outbound_manager;
}

void DefaultDispatcher::BindRuleManager(rule::Manager& rule_manager) noexcept {
    rule_manager_ = &rule_manager;
}

void DefaultDispatcher::BindSessionTracking(
    app::SessionTrackingState& session_tracking) noexcept {
    session_tracking_ = &session_tracking;
}

void DefaultDispatcher::BindDnsService(app::dns::DNS& dns_service) noexcept {
    dns_service_ = &dns_service;
}

features::outbound::Handler* DefaultDispatcher::ResolveOutboundHandler(
    std::string_view tag) const noexcept {
    if (!outbound_manager_) {
        return nullptr;
    }
    if (tag.empty()) {
        return outbound_manager_->GetDefaultHandler();
    }
    return outbound_manager_->GetHandler(tag);
}

net::awaitable<RelayResult> DefaultDispatcher::Dispatch(
    net::io_context& io_context,
    const proxyman::inbound::ReceiverSettings& receiver,
    std::unique_ptr<AsyncStream> inbound,
    transport::Link inbound_link,
    InitialPayload first_packet,
    session::Context& ctx,
    StatsShard& stats,
    const TimeoutsConfig& timeouts,
    uint32_t pressure_idle_timeout) {
    co_return co_await DispatchPreparedLink(
        io_context,
        receiver,
        std::move(inbound),
        inbound_link,
        std::move(first_packet),
        ctx,
        stats,
        timeouts,
        pressure_idle_timeout);
}

net::awaitable<RelayResult> DefaultDispatcher::DispatchPreparedLink(
    net::io_context& io_context,
    const proxyman::inbound::ReceiverSettings& receiver,
    std::unique_ptr<AsyncStream> inbound,
    transport::Link inbound_link,
    InitialPayload first_packet,
    session::Context& ctx,
    StatsShard& stats,
    const TimeoutsConfig& timeouts,
    uint32_t pressure_idle_timeout) {

    const bool has_protocol_link = inbound_link.Valid();
    if (!inbound && !has_protocol_link) {
        stats.OnError();
        co_return MakeRelayError(ErrorCode::PROTOCOL_DECODE_FAILED);
    }
    AsyncStream* inbound_endpoint = inbound.get();
    transport::MultiBufferReader* inbound_reader =
        has_protocol_link ? inbound_link.reader : inbound_endpoint;
    transport::MultiBufferWriter* inbound_writer =
        has_protocol_link ? inbound_link.writer : inbound_endpoint;
    AsyncStream* inbound_control =
        inbound_link.control ? inbound_link.control : inbound_endpoint;
    if (inbound_control) {
        (void)inbound_control->ConsumePhaseDeadline();
        inbound_control->ClearPhaseDeadline();
    }

    LOG_CONN_DEBUG(ctx, "[Session] Protocol auth ok: [{}] -> {} user={}",
                   ctx.inbound.tag, ctx.outbound.original_target, ctx.inbound.user_email);

    if (ctx.content.network == Network::MUX) {
        LOG_ACCESS(FormatAccessLog(ctx));

        const auto relay_idle_timeout = ResolveRelayIdleTimeout(
            timeouts, pressure_idle_timeout);
        if (inbound_endpoint) {
            inbound_endpoint->SetIdleTimeout(relay_idle_timeout);
            inbound_endpoint->SetReadTimeout(std::chrono::seconds(0));
            inbound_endpoint->SetWriteTimeout(
                std::min(timeouts.WriteTimeout(), relay_idle_timeout));
        }

        UDPRelayConfig mux_cfg;
        mux_cfg.speed_limit = ctx.content.speed_limit;

        ActiveSessionScope relay_scope{ctx, session_tracking_};
        auto relay_result = co_await mux::DoMuxRelay(
            io_context,
            transport::Link{inbound_reader, inbound_writer, inbound_control},
            inbound_control,
            *this,
            receiver,
            ctx,
            stats,
            timeouts,
            pressure_idle_timeout,
            mux_cfg);
        if (relay_result.error != ErrorCode::OK) {
            LOG_CONN_DEBUG(ctx, "[Session] Mux relay end: {} up={}B down={}B target={}",
                           ErrorCodeToString(relay_result.error),
                           ctx.traffic.bytes_up, ctx.traffic.bytes_down,
                           ctx.outbound.target);
        }
        co_return relay_result;
    }

    // 嗅探只需首部若干字节即可解析 TLS ClientHello SNI / HTTP Host；
    // 首包很大（例如客户端把大块 body pipeline 进首包）时无需整包拷贝。
    static constexpr size_t kSniffMaxBytes = 4096;
    buf::MultiBuffer outbound_first_payload;
    size_t outbound_first_payload_size = 0;
    std::span<const uint8_t> sniff_data;
    memory::ByteVector sniff_scratch;

    auto sniff_from_multibuffer = [&](const buf::MultiBuffer& mb, size_t total) {
        if (total == 0) {
            return;
        }
        const size_t want = std::min(total, kSniffMaxBytes);
        if (auto direct = mb.PrefixSpan(want); !direct.empty()) {
            sniff_data = direct;
            return;
        }
        sniff_scratch.resize(want);
        const size_t copied = mb.CopyPrefixTo(
            std::span<uint8_t>(sniff_scratch.data(), sniff_scratch.size()));
        if (copied > 0) {
            sniff_data = std::span<const uint8_t>(sniff_scratch.data(), copied);
        }
    };

    if (receiver.sniff_config.enabled) {
        if (!first_packet.empty()) {
            if (first_packet.IsContiguous()) {
                sniff_data = first_packet.span();
                if (sniff_data.size() > kSniffMaxBytes) {
                    sniff_data = sniff_data.first(kSniffMaxBytes);
                }
            } else {
                const size_t want = std::min(first_packet.size(), kSniffMaxBytes);
                if (auto direct = first_packet.PrefixSpan(want); !direct.empty()) {
                    sniff_data = direct;
                } else {
                    sniff_scratch.resize(want);
                    const size_t got = first_packet.CopyPrefixTo(
                        sniff_scratch.data(), sniff_scratch.size());
                    if (got > 0) {
                        sniff_data = std::span<const uint8_t>(sniff_scratch.data(), got);
                    }
                }
            }
        } else if (ctx.content.network == Network::TCP && inbound_reader) {
            try {
                if (inbound_control) {
                    inbound_control->SetReadTimeout(timeouts.ReadTimeout());
                }
                outbound_first_payload = co_await inbound_reader->ReadMultiBuffer();
                outbound_first_payload_size = buf::TotalLen(outbound_first_payload);
                if (outbound_first_payload_size > 0) {
                    LOG_CONN_DEBUG(ctx, "[Session] Sniff prefetch payload={}B",
                                   outbound_first_payload_size);
                    sniff_from_multibuffer(
                        outbound_first_payload,
                        outbound_first_payload_size);
                }
            } catch (const IoSystemError& e) {
                stats.OnError();
                co_return MakeRelayError(inbound_control && inbound_control->ConsumeReadTimeout()
                    ? ErrorCode::TIMEOUT
                    : MapAsioError(e.code()));
            } catch (...) {
                stats.OnError();
                co_return MakeRelayError(ErrorCode::SOCKET_READ_FAILED);
            }
        }
    }

    if (!sniff_data.empty()) {
        auto result = Sniff(sniff_data);

        if (result.success && !result.domain.empty()) {
            const std::string_view sniff_domain(result.domain.data(), result.domain.size());
            LOG_CONN_DEBUG(ctx, "[Session] Sniff: proto={} domain={}",
                           result.protocol, sniff_domain);

            bool excluded = false;
            for (const auto& ex : receiver.sniff_config.domains_excluded) {
                if (sniff_domain == ex) {
                    excluded = true;
                    break;
                }
            }

            if (receiver.sniff_config.MatchesDestOverride(result.protocol) && !excluded) {
                const uint16_t final_port = result.port > 0
                    ? result.port
                    : ctx.outbound.original_target.port;
                IoErrorCode sniff_ip_ec;
                auto sniff_ip = net::ip::make_address(sniff_domain, sniff_ip_ec);
                if (!sniff_ip_ec) {
                    sniff_ip = iputil::NormalizeAddress(sniff_ip);
                    ctx.outbound.target = TargetAddress(sniff_ip, final_port);
                    ctx.outbound.route_target = ctx.outbound.target;
                } else {
                    TargetAddress final_target;
                    final_target.type = AddressType::Domain;
                    final_target.host.assign(sniff_domain);
                    final_target.resolved_addr.reset();
                    final_target.port = final_port;
                    ctx.outbound.target = std::move(final_target);
                    ctx.outbound.route_target = ctx.outbound.target;
                }
            }
        }

        if (result.success) {
            ctx.content.protocol.assign(result.protocol.data(), result.protocol.size());
            ctx.content.sniff_domain.assign(result.domain.data(), result.domain.size());
        }
    }

    const routing::DispatchResult dispatch = co_await RouteAsync(ctx, &receiver);
    auto* outbound_handler = dispatch.handler;
    if (!outbound_handler) {
        if (dispatch.error == ErrorCode::BLOCKED) {
            LOG_CONN_FAIL_CTX(ctx, "RULE_REJECT user={} target={}",
                              ctx.inbound.user_email, ctx.outbound.target);
            stats.OnError();
            co_return MakeRelayError(ErrorCode::BLOCKED);
        }
        LOG_CONN_FAIL_CTX(ctx, "OUTBOUND_HANDLER_NOT_FOUND {} -> {} via {}",
                          ctx.inbound.source_ip, ctx.outbound.target, ctx.outbound.tag);
        stats.OnError();
        co_return MakeRelayError(ErrorCode::ROUTER_OUTBOUND_NOT_FOUND);
    }

    // UDP 与 TCP 共用主链路：dispatcher.Dispatch -> outbound.Process -> relay。
    // UDP 数据面（Full Cone + framer）下沉到 UDP-capable 出站的 Process，由下方
    // 通用路径设置入站 idle/write timeout 并调用 outbound_handler->Dispatch。

    std::optional<tcp::endpoint> inbound_local_addr =
        inbound_endpoint ? inbound_endpoint->LocalEndpoint() : std::nullopt;
    if (!inbound_local_addr && ctx.inbound.local_endpoint) {
        inbound_local_addr = ctx.inbound.local_endpoint;
    }
    const auto relay_idle_timeout = ResolveRelayIdleTimeout(
        timeouts, pressure_idle_timeout);
    if (pressure_idle_timeout > 0 &&
        relay_idle_timeout < timeouts.StreamIdleTimeout()) {
        LOG_CONN_DEBUG(ctx,
                       "[Session] Pressure mode: relay_idle={}s -> {}s",
                       timeouts.StreamIdleTimeout().count(),
                       relay_idle_timeout.count());
    }
    const auto relay_write_timeout =
        std::min(timeouts.WriteTimeout(), relay_idle_timeout);
    if (inbound_endpoint) {
        inbound_endpoint->SetIdleTimeout(relay_idle_timeout);
        inbound_endpoint->SetReadTimeout(std::chrono::seconds(0));
        inbound_endpoint->SetWriteTimeout(relay_write_timeout);
    }

    RelayConfig relay_cfg;
    relay_cfg.uplink_only   = timeouts.UplinkOnlyTimeout();
    relay_cfg.downlink_only = timeouts.DownlinkOnlyTimeout();
    relay_cfg.speed_limit   = ctx.content.speed_limit;

    if (outbound_first_payload_size == 0 &&
        !first_packet.empty() && !first_packet.IsContiguous()) {
        outbound_first_payload = first_packet.MoveToMultiBuffer();
        outbound_first_payload_size = buf::TotalLen(outbound_first_payload);
    }
    const bool use_owned_first_payload = outbound_first_payload_size > 0;
    const size_t relay_payload_size = use_owned_first_payload
        ? outbound_first_payload_size
        : first_packet.size();

    LOG_CONN_DEBUG(ctx, "[Session] Relay start: {} -> {} via {} payload={}B",
                   ctx.inbound.source_ip, ctx.outbound.target, ctx.outbound.tag,
                   relay_payload_size);

    ActiveSessionScope relay_scope{ctx, session_tracking_};
    auto outbound_process = co_await outbound_handler->Dispatch(
        io_context,
        inbound_local_addr ? &*inbound_local_addr : nullptr,
        ctx,
        timeouts,
        transport::Link{inbound_reader, inbound_writer, inbound_control},
        relay_cfg,
        use_owned_first_payload
            ? std::span<const uint8_t>{}
            : first_packet.span(),
        outbound_first_payload,
        relay_idle_timeout,
        relay_write_timeout);
    if (!outbound_process) {
        stats.OnError();
        co_return MakeRelayError(ErrorCode::OUTBOUND_CONNECTION_FAILED);
    }
    RelayResult relay_result = std::move(*outbound_process);

    if (relay_result.error != ErrorCode::OK) {
        LOG_CONN_DEBUG(ctx, "[Session] Relay end: {} up={}B down={}B closer={} target={}",
                       ErrorCodeToString(relay_result.error),
                       ctx.traffic.bytes_up, ctx.traffic.bytes_down,
                       relay_result.client_closed_first ? "client" : "target",
                       ctx.outbound.target);
    } else {
        LOG_CONN_DEBUG(ctx, "[Session] Relay end: OK up={}B down={}B target={}",
                       ctx.traffic.bytes_up, ctx.traffic.bytes_down,
                       ctx.outbound.target);
    }
    co_return relay_result;
}

routing::DispatchResult DefaultDispatcher::FinishRoute(
    session::Context& ctx,
    const RouteSelection& selection) const noexcept {
    if (selection.error != ErrorCode::OK) {
        LOG_CONN_FAIL_CTX(ctx, "DISPATCHER_NOT_BOUND {} -> {}",
                          ctx.inbound.source_ip, ctx.outbound.target);
        return routing::DispatchResult{.error = selection.error};
    }

    ctx.outbound.tag = selection.outbound_tag;
    if (selection.fixed) {
        LOG_CONN_DEBUG(ctx, "[Dispatcher] {} -> outbound={} (fixed)",
                       ctx.outbound.target, ctx.outbound.tag);
    } else {
        LOG_CONN_DEBUG(ctx, "[Dispatcher] {} -> outbound={}",
                       ctx.outbound.target, ctx.outbound.tag);
    }

    if (rule_manager_ && ctx.inbound.user_id > 0 &&
        rule_manager_->HasRule(ctx.inbound.tag)) {
        // Worker-local 复用 destination scratch，省去每连接的 target 串分配。
        thread_local std::string rule_dest;
        ctx.outbound.target.ToStringInto(rule_dest);
        if (rule_manager_->Detect(
                ctx.inbound.tag,
                rule_dest,
                std::string_view(ctx.inbound.user_email.data(),
                                 ctx.inbound.user_email.size()))) {
            return routing::DispatchResult{.error = ErrorCode::BLOCKED};
        }
    }

    auto* handler = ResolveOutboundHandler(selection.outbound_tag);
    if (handler && ctx.outbound.tag.empty()) {
        const auto handler_tag = handler->Tag();
        ctx.outbound.tag = handler_tag;
    }
    if (!handler) {
        return routing::DispatchResult{.error = ErrorCode::ROUTER_OUTBOUND_NOT_FOUND};
    }

    return routing::DispatchResult{
        .handler = handler,
        .error = ErrorCode::OK,
    };
}

DefaultDispatcher::RouteSelection DefaultDispatcher::SelectRoute(
    session::Context& ctx,
    const proxyman::inbound::ReceiverSettings* receiver) const noexcept {
    if (receiver &&
        receiver->route_policy.kind == proxyman::inbound::RoutePolicyKind::FixedOutbound) {
        return RouteSelection{
            .outbound_tag = receiver->route_policy.outbound_tag,
            .matched = true,
            .fixed = true,
            .error = ErrorCode::OK,
        };
    }

    if (!router_) {
        RouteSelection selection;
        selection.error = ErrorCode::ROUTER_OUTBOUND_NOT_FOUND;
        return selection;
    }

    app::router::RouteDecision decision;
    if (receiver &&
        receiver->route_policy.kind == proxyman::inbound::RoutePolicyKind::RouteWithFallback) {
        decision = router_->RouteDetailed(ctx, receiver->route_policy.outbound_tag);
    } else {
        decision = router_->RouteDetailed(ctx);
    }

    return RouteSelection{
        .outbound_tag = decision.outbound_tag,
        .matched = decision.matched,
        .fixed = false,
        .error = ErrorCode::OK,
    };
}

routing::DispatchResult DefaultDispatcher::Route(
    session::Context& ctx,
    const proxyman::inbound::ReceiverSettings& receiver) const noexcept {
    return FinishRoute(ctx, SelectRoute(ctx, &receiver));
}

routing::DispatchResult DefaultDispatcher::Route(session::Context& ctx) const noexcept {
    return FinishRoute(ctx, SelectRoute(ctx, nullptr));
}

net::awaitable<routing::DispatchResult> DefaultDispatcher::RouteAsync(
    session::Context& ctx,
    const proxyman::inbound::ReceiverSettings* receiver) {
    if (!router_ ||
        (receiver &&
         receiver->route_policy.kind == proxyman::inbound::RoutePolicyKind::FixedOutbound) ||
        !ctx.outbound.target.IsDomain() ||
        ctx.outbound.target.resolved_addr) {
        co_return FinishRoute(ctx, SelectRoute(ctx, receiver));
    }

    const auto strategy = router_->DomainStrategy();
    if (strategy == app::router::RoutingDomainStrategy::AsIs || !dns_service_) {
        co_return FinishRoute(ctx, SelectRoute(ctx, receiver));
    }

    auto select_with_addresses =
        [&](const std::vector<net::ip::address>& addresses) -> RouteSelection {
            RouteSelection last;
            for (const auto& addr : addresses) {
                ctx.outbound.target.resolved_addr = addr;
                if (ctx.outbound.route_target.IsDomain() &&
                    ctx.outbound.route_target.host == ctx.outbound.target.host &&
                    ctx.outbound.route_target.port == ctx.outbound.target.port) {
                    ctx.outbound.route_target.resolved_addr = addr;
                }
                auto selection = SelectRoute(ctx, receiver);
                last = selection;
                if (selection.error != ErrorCode::OK || selection.fixed || selection.matched) {
                    return selection;
                }
            }
            if (!addresses.empty()) {
                ctx.outbound.target.resolved_addr = addresses.front();
            }
            return last;
        };

    if (strategy == app::router::RoutingDomainStrategy::IPIfNonMatch) {
        auto initial = SelectRoute(ctx, receiver);
        if (initial.error != ErrorCode::OK || initial.fixed || initial.matched) {
            co_return FinishRoute(ctx, initial);
        }

        auto addresses = co_await ResolveRoutingAddresses(*dns_service_, ctx);
        if (!addresses.empty()) {
            co_return FinishRoute(ctx, select_with_addresses(addresses));
        }
        co_return FinishRoute(ctx, initial);
    }

    auto addresses = co_await ResolveRoutingAddresses(*dns_service_, ctx);
    if (!addresses.empty()) {
        co_return FinishRoute(ctx, select_with_addresses(addresses));
    }
    co_return FinishRoute(ctx, SelectRoute(ctx, receiver));
}

}  // namespace acpp::app::dispatcher
