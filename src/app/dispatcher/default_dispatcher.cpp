#include "acppnode/app/dispatcher/default_dispatcher.hpp"

#include "outbound_selection.hpp"
#include "../../common/awaitable_task_group.hpp"

#include "acppnode/app/stats.hpp"
#include "acppnode/app/session_tracking.hpp"
#include "acppnode/app/request_load_state.hpp"
#include "acppnode/app/dns/dns.hpp"
#include "acppnode/common/session.hpp"
#include "acppnode/features/policy/request_policy.hpp"
#include "acppnode/features/outbound/outbound.hpp"
#include "acppnode/proxy/outbound.hpp"
#include "acppnode/infra/runtime_config_types.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/features/routing/router.hpp"
#include "acppnode/sniff/sniffer.hpp"
#include "acppnode/transport/link.hpp"
#include "acppnode/transport/async_stream.hpp"
#include "acppnode/common/buf/multi_buffer.hpp"

#include <algorithm>
#include <asio/experimental/awaitable_operators.hpp>
#include <asio/steady_timer.hpp>
#include <asio/this_coro.hpp>
#include <asio/use_awaitable.hpp>
#include <chrono>
#include <limits>
#include <new>
#include <string>
#include <vector>

namespace acpp::app::dispatcher {

namespace {

void ApplySniffOverride(
    session::Context& ctx,
    const SniffConfig& sniffing,
    const SniffResult& result) {
    if (!result.success) {
        return;
    }
    ctx.content.protocol.assign(result.protocol.data(), result.protocol.size());
    ctx.content.sniff_domain.assign(result.domain.data(), result.domain.size());
    if (result.domain.empty()) {
        return;
    }
    const std::string_view sniff_domain(result.domain.data(), result.domain.size());
    LOG_CONN_DEBUG(ctx, "[Session] Sniff: proto={} domain={}",
                   result.protocol, sniff_domain);
    if (sniffing.IsDomainExcluded(sniff_domain) ||
        !sniffing.MatchesDestOverride(result.protocol)) {
        return;
    }
    const uint16_t final_port = result.port > 0
        ? result.port
        : ctx.outbound.original_target.port;
    TargetAddress sniffed(sniff_domain, final_port);
    if (!sniffed.IsValid()) {
        return;
    }
    ctx.outbound.route_target = sniffed;
    if (!sniffing.route_only) {
        ctx.outbound.target = std::move(sniffed);
    }
}

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

    const int64_t started_at_us = NowMicros();
    auto dns_result = co_await dns_service.Resolve(target.host);
    // DNS may return a failed result after cancellation. Do not publish that
    // result into the request or continue to route/outbound lookup.
    const auto cancellation = co_await net::this_coro::cancellation_state;
    if (cancellation.cancelled() != net::cancellation_type::none)
        throw IoSystemError(net::error::operation_aborted);
    const int64_t elapsed_us = std::max<int64_t>(0, NowMicros() - started_at_us);
    ctx.outbound.dns_latency_ms = static_cast<uint32_t>(
        std::min<int64_t>(elapsed_us / 1000, std::numeric_limits<uint32_t>::max()));
    ctx.outbound.dns_answer_count = static_cast<uint32_t>(
        std::min<size_t>(dns_result.addresses.size(), std::numeric_limits<uint32_t>::max()));
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

void DefaultDispatcher::BindRouter(const routing::Router& router) noexcept {
    router_ = &router;
}

void DefaultDispatcher::BindOutboundManager(
    features::outbound::Manager& outbound_manager) noexcept {
    outbound_manager_ = &outbound_manager;
}

void DefaultDispatcher::BindRequestPolicy(
    features::policy::RequestPolicy& request_policy) noexcept {
    request_policy_ = &request_policy;
}

void DefaultDispatcher::BindSessionTracking(
    app::SessionTrackingState& session_tracking) noexcept {
    session_tracking_ = &session_tracking;
}

void DefaultDispatcher::BindDnsService(app::dns::DNS& dns_service) noexcept {
    dns_service_ = &dns_service;
}

void DefaultDispatcher::BindRequestLoadState(
    app::RequestLoadState& request_load) noexcept {
    request_load_ = &request_load;
}

std::shared_ptr<Outbound> DefaultDispatcher::ResolveOutboundHandler(
    std::string_view tag) const noexcept {
    if (!outbound_manager_) {
        return nullptr;
    }
    return outbound_manager_->GetHandler(tag);
}

net::awaitable<RelayResult> DefaultDispatcher::Dispatch(
    net::io_context& io_context,
    const routing::DispatchPolicy& policy,
    std::unique_ptr<AsyncStream> inbound,
    transport::Link inbound_link,
    InitialPayload first_packet,
    session::Context& ctx,
    StatsShard& stats,
    const TimeoutsConfig& timeouts) {
    app::RequestLoadState::DispatchScope load_scope(request_load_);
    const uint32_t pressure_idle_timeout = request_load_
        ? request_load_->PressureIdleTimeout()
        : 0;
    const int64_t auth_completed_at_us = NowMicros();
    const int64_t auth_started_at_us = ctx.inbound.transport_ready_at_unix_us > 0
        ? ctx.inbound.transport_ready_at_unix_us
        : ctx.accept_time_us;
    if (ctx.auth_ms == 0 && auth_started_at_us > 0 &&
        auth_completed_at_us >= auth_started_at_us) {
        ctx.auth_ms = static_cast<uint32_t>(std::min<int64_t>(
            (auth_completed_at_us - auth_started_at_us) / 1000,
            std::numeric_limits<uint32_t>::max()));
    }
    RelayResult result;
    ErrorCode cancellation_reason = ErrorCode::OK;
    try {
        co_await RunAwaitableTaskGroup(io_context.get_executor(), [&](AwaitableTaskGroup& group) {
            group.Spawn(DispatchPreparedLink(
                io_context, policy, std::move(inbound), inbound_link,
                std::move(first_packet), ctx, stats, timeouts, pressure_idle_timeout,
                result, group, cancellation_reason));
        });
    } catch (const std::bad_alloc&) {
        stats.OnError();
        result = MakeRelayError(ErrorCode::RESOURCE_EXHAUSTED);
        LOG_CONN_WARN(ctx, "failed to process outbound traffic > out of memory");
    } catch (const IoSystemError& e) {
        stats.OnError();
        result = MakeRelayError(MapAsioError(e.code()));
        ctx.outbound.os_error_code = e.code().value();
        ctx.outbound.failure_detail_code = ErrorCodeToString(result.error);
        LOG_CONN_WARN(ctx, "failed to process outbound traffic > {}", e.what());
    } catch (const std::exception& e) {
        stats.OnError();
        result = MakeRelayError(ErrorCode::INTERNAL);
        LOG_CONN_WARN(ctx, "failed to process outbound traffic > {}", e.what());
    } catch (...) {
        stats.OnError();
        result = MakeRelayError(ErrorCode::INTERNAL);
        LOG_CONN_WARN(ctx, "failed to process outbound traffic > unknown error");
    }
    if (result.error == ErrorCode::CANCELLED && cancellation_reason != ErrorCode::OK) {
        result.error = cancellation_reason;
        ctx.outbound.failure_detail_code = ErrorCodeToString(result.error);
    }
    co_return result;
}

net::awaitable<void> DefaultDispatcher::DispatchPreparedLink(
    net::io_context& io_context,
    const routing::DispatchPolicy& policy,
    std::unique_ptr<AsyncStream> inbound,
    transport::Link inbound_link,
    InitialPayload first_packet,
    session::Context& ctx,
    StatsShard& stats,
    const TimeoutsConfig& timeouts,
    uint32_t pressure_idle_timeout,
    RelayResult& result,
    AwaitableTaskGroup& request_group,
    ErrorCode& cancellation_reason) {

    struct CancellationContext {
        AwaitableTaskGroup& group;
        ErrorCode& reason;
    } cancellation{request_group, cancellation_reason};
    const auto cancel = [](void* raw, transport::Cancellation event) noexcept {
        auto& state = *static_cast<CancellationContext*>(raw);
        state.reason = event.reason == ErrorCode::OK ? ErrorCode::CANCELLED : event.reason;
        state.group.Cancel();
    };
    auto* cancellation_reader = inbound_link.Valid() ? inbound_link.reader : inbound.get();
    std::optional<transport::CancellationSubscription> subscription;
    if (cancellation_reader) {
        subscription.emplace(cancellation_reader->Cancellation(), cancel, &cancellation);
    }
    if (cancellation_reason != ErrorCode::OK) {
        stats.OnError();
        result = MakeRelayError(cancellation_reason);
        co_return;
    }

    const bool has_protocol_link = inbound_link.Valid();
    if (!inbound && !has_protocol_link) {
        stats.OnError();
        result = MakeRelayError(ErrorCode::PROTOCOL_DECODE_FAILED);
        co_return;
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

    if (!ctx.outbound.target.IsValid()) {
        stats.OnError();
        LOG_CONN_DEBUG(ctx, "[Session] Reject invalid outbound target");
        result = MakeRelayError(ErrorCode::PROTOCOL_DECODE_FAILED);
        co_return;
    }

    LOG_CONN_DEBUG(ctx, "[Session] Protocol auth ok: [{}] -> {} user={}",
                   ctx.inbound.tag, ctx.outbound.original_target, ctx.inbound.user_email);

    buf::MultiBuffer outbound_first_payload;
    if (policy.sniffing.enabled && !policy.sniffing.metadata_only) {
        using net::experimental::awaitable_operators::operator||;
        static constexpr size_t kSniffMaxBytes = 4096;
        buf::MultiBuffer sniff_payload;
        static constexpr auto kTcpSniffWindow = std::chrono::milliseconds(200);
        static constexpr auto kUdpSniffWindow = std::chrono::seconds(3);
        const auto sniff_window = ctx.content.network == Network::UDP
            ? std::chrono::duration_cast<std::chrono::milliseconds>(kUdpSniffWindow)
            : kTcpSniffWindow;
        memory::ByteVector sniff_scratch;

        auto copy_cached_bytes = [&](const buf::MultiBuffer& mb) {
            const size_t total = buf::TotalLen(mb);
            if (total == 0) {
                return std::span<const uint8_t>{};
            }
            const size_t want = std::min(total, kSniffMaxBytes);
            if (auto direct = mb.PrefixSpan(want); !direct.empty()) {
                return direct;
            }
            sniff_scratch.resize(want);
            const size_t copied = mb.CopyPrefixTo(
                std::span<uint8_t>(sniff_scratch.data(), sniff_scratch.size()));
            return copied == 0
                ? std::span<const uint8_t>{}
                : std::span<const uint8_t>(sniff_scratch.data(), copied);
        };

        auto sniff_cached = [&]() {
            const auto sniff_data = copy_cached_bytes(sniff_payload);
            if (sniff_data.empty()) {
                return SniffResult{};
            }
            return Sniff(sniff_data, ctx.content.network);
        };

        try {
            if (inbound_reader) {
                auto cache_more = [&]() -> net::awaitable<bool> {
                    auto payload = co_await inbound_reader->ReadMultiBuffer();
                    if (payload.empty()) {
                        co_return false;
                    }
                    payload.MoveTo(sniff_payload);
                    co_return true;
                };
                if (!first_packet.empty()) {
                    sniff_payload = first_packet.MoveToMultiBuffer();
                } else {
                    if (inbound_control) {
                        inbound_control->SetReadTimeout(timeouts.ReadTimeout());
                    }
                    (void)co_await cache_more();
                }

                const auto sniff_started = std::chrono::steady_clock::now();
                int no_clue_attempts = 0;
                for (;;) {
                    const auto sniffed = sniff_cached();
                    if (sniffed.success) {
                        ApplySniffOverride(ctx, policy.sniffing, sniffed);
                        break;
                    }
                    if (!sniffed.need_more) {
                        ++no_clue_attempts;
                        if (no_clue_attempts >= 2) {
                            break;
                        }
                    }
                    if (buf::TotalLen(sniff_payload) >= kSniffMaxBytes) {
                        break;
                    }
                    const auto remaining = sniff_window -
                        std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::steady_clock::now() - sniff_started);
                    if (remaining <= std::chrono::milliseconds::zero()) {
                        break;
                    }
                    const auto bytes_before = buf::TotalLen(sniff_payload);
                    net::steady_timer timer(io_context);
                    timer.expires_after(remaining);
                    try {
                        co_await (cache_more() ||
                                  timer.async_wait(net::use_awaitable));
                    } catch (...) {
                        break;
                    }
                    if (buf::TotalLen(sniff_payload) <= bytes_before) {
                        break;
                    }
                }
                outbound_first_payload = std::move(sniff_payload);
            } else if (!first_packet.empty()) {
                const auto sniff_data = first_packet.IsContiguous()
                    ? first_packet.span()
                    : std::span<const uint8_t>{};
                memory::ByteVector leftover;
                std::span<const uint8_t> view = sniff_data;
                if (view.empty()) {
                    const size_t want =
                        std::min(first_packet.size(), kSniffMaxBytes);
                    leftover.resize(want);
                    const size_t got = first_packet.CopyPrefixTo(
                        leftover.data(), leftover.size());
                    if (got > 0) {
                        view = std::span<const uint8_t>(leftover.data(), got);
                    }
                } else if (view.size() > kSniffMaxBytes) {
                    view = view.first(kSniffMaxBytes);
                }
                if (!view.empty()) {
                    ApplySniffOverride(
                        ctx, policy.sniffing, Sniff(view, ctx.content.network));
                }
            }
        } catch (const std::bad_alloc&) {
            throw;
        } catch (const transport::LinkError& e) {
            stats.OnError();
            result = MakeRelayError(e.code());
            co_return;
        } catch (const IoSystemError& e) {
            stats.OnError();
            result = MakeRelayError(inbound_control && inbound_control->ConsumeReadTimeout()
                ? ErrorCode::TIMEOUT
                : MapAsioError(e.code()));
            co_return;
        } catch (...) {
            stats.OnError();
            result = MakeRelayError(ErrorCode::SOCKET_READ_FAILED);
            co_return;
        }
    }

    RouteResult dispatch = co_await RouteAsync(ctx, policy);
    auto outbound_handler = std::move(dispatch.handler);
    if (!outbound_handler) {
        if (dispatch.error == ErrorCode::BLOCKED) {
            LOG_CONN_WARN(ctx, "destination rejected user={} target={}",
                              ctx.inbound.user_email, ctx.outbound.target);
            stats.OnError();
            result = MakeRelayError(ErrorCode::BLOCKED);
            co_return;
        }
        LOG_CONN_WARN(ctx, "failed to find outbound handler {} -> {} via {}",
                          ctx.inbound.source_ip, ctx.outbound.target, ctx.outbound.tag);
        stats.OnError();
        result = MakeRelayError(ErrorCode::ROUTER_OUTBOUND_NOT_FOUND);
        co_return;
    }

    // UDP 与 TCP 共用主链路：dispatcher.Dispatch -> outbound.Process -> relay。
    // UDP 数据面（Full Cone + framer）下沉到 UDP-capable 出站的 Process，由下方
    // 通用路径设置入站 idle/write timeout 并调用 outbound.Process。

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

    if (outbound_first_payload.empty() && !first_packet.empty()) {
        outbound_first_payload = first_packet.MoveToMultiBuffer();
    }
    const size_t relay_payload_size = buf::TotalLen(outbound_first_payload);

    LOG_CONN_DEBUG(ctx, "[Session] Relay start: {} -> {} via {} payload={}B",
                   ctx.inbound.source_ip, ctx.outbound.target, ctx.outbound.tag,
                   relay_payload_size);

    ActiveSessionScope relay_scope{ctx, session_tracking_};
    auto outbound_process = co_await outbound_handler->Process(
        io_context,
        inbound_local_addr ? &*inbound_local_addr : nullptr,
        ctx,
        timeouts,
        transport::Link{inbound_reader, inbound_writer, inbound_control},
        stats,
        relay_cfg,
        std::move(outbound_first_payload),
        relay_idle_timeout,
        relay_write_timeout);
    if (!outbound_process) {
        ErrorCode process_error = outbound_process.error();
        if (process_error == ErrorCode::OK) {
            process_error = ErrorCode::PROTOCOL_AUTH_FAILED;
        }
        LOG_CONN_WARN(ctx, "failed to process outbound traffic {} -> {} via {} > {}",
                          ctx.inbound.source_ip, ctx.outbound.target,
                          ctx.outbound.tag, ErrorCodeToLogReason(process_error));
        stats.OnError();
        result = MakeRelayError(process_error);
        co_return;
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
    result = std::move(relay_result);
    co_return;
}

DefaultDispatcher::RouteResult DefaultDispatcher::FinishRoute(
    session::Context& ctx,
    const detail::OutboundSelection& selection) const {
    ctx.outbound.tag = selection.outbound_tag;
    switch (selection.source) {
        case detail::SelectionSource::Forced:
            ctx.outbound.route_rule = "fixed";
            break;
        case detail::SelectionSource::Rule:
            ctx.outbound.route_rule =
                "rule:" + std::to_string(selection.rule_index);
            break;
        case detail::SelectionSource::Fallback:
            ctx.outbound.route_rule = "fallback";
            break;
    }
    if (selection.source == detail::SelectionSource::Forced) {
        LOG_CONN_DEBUG(ctx, "[Dispatcher] {} -> outbound={} (fixed)",
                       ctx.outbound.target, ctx.outbound.tag);
    } else {
        LOG_CONN_DEBUG(ctx, "[Dispatcher] {} -> outbound={}",
                       ctx.outbound.target, ctx.outbound.tag);
    }

    if (request_policy_ && request_policy_->Blocked(ctx)) {
        return RouteResult{
            .handler = {},
            .error = ErrorCode::BLOCKED,
        };
    }

    auto handler = ResolveOutboundHandler(selection.outbound_tag);
    if (!handler) {
        return RouteResult{
            .handler = {},
            .error = ErrorCode::ROUTER_OUTBOUND_NOT_FOUND,
        };
    }

    return RouteResult{
        .handler = std::move(handler),
        .error = ErrorCode::OK,
    };
}

detail::OutboundSelection DefaultDispatcher::SelectRoute(
    session::Context& ctx,
    const routing::DispatchPolicy& policy) const {
    routing::RouteDecision decision;
    if (router_ && detail::RequiresRouting(policy.outbound)) {
        decision = router_->Route(ctx);
    }

    return detail::SelectOutbound(policy.outbound, decision);
}

net::awaitable<DefaultDispatcher::RouteResult> DefaultDispatcher::RouteAsync(
    session::Context& ctx,
    const routing::DispatchPolicy& policy) {
    if (!router_ || !detail::RequiresRouting(policy.outbound) ||
        !ctx.outbound.target.IsDomain() ||
        ctx.outbound.target.resolved_addr) {
        co_return FinishRoute(ctx, SelectRoute(ctx, policy));
    }

    const auto strategy = router_->DomainStrategy();
    if (strategy == routing::DomainStrategy::AsIs || !dns_service_) {
        co_return FinishRoute(ctx, SelectRoute(ctx, policy));
    }

    auto select_with_addresses =
        [&](const std::vector<net::ip::address>& addresses) -> detail::OutboundSelection {
            auto select_address = [&](const net::ip::address& addr) {
                ctx.outbound.target.resolved_addr = addr;
                if (ctx.outbound.route_target.IsDomain() &&
                    ctx.outbound.route_target.host == ctx.outbound.target.host &&
                    ctx.outbound.route_target.port == ctx.outbound.target.port) {
                    ctx.outbound.route_target.resolved_addr = addr;
                }
                return SelectRoute(ctx, policy);
            };

            auto address = addresses.begin();
            auto last = select_address(*address);
            if (last.source != detail::SelectionSource::Fallback) {
                return last;
            }
            for (++address; address != addresses.end(); ++address) {
                auto selection = select_address(*address);
                last = selection;
                if (selection.source != detail::SelectionSource::Fallback) {
                    return selection;
                }
            }
            ctx.outbound.target.resolved_addr = addresses.front();
            return last;
        };

    if (strategy == routing::DomainStrategy::IPIfNonMatch) {
        auto initial = SelectRoute(ctx, policy);
        if (initial.source != detail::SelectionSource::Fallback) {
            co_return FinishRoute(ctx, initial);
        }

        auto addresses = co_await ResolveRoutingAddresses(*dns_service_, ctx);
        if (!addresses.empty()) {
            co_return FinishRoute(ctx, select_with_addresses(addresses));
        }
        co_return FinishRoute(ctx, SelectRoute(ctx, policy));
    }

    auto addresses = co_await ResolveRoutingAddresses(*dns_service_, ctx);
    if (!addresses.empty()) {
        co_return FinishRoute(ctx, select_with_addresses(addresses));
    }
    co_return FinishRoute(ctx, SelectRoute(ctx, policy));
}

}  // namespace acpp::app::dispatcher
