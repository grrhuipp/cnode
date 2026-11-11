#include "app/dispatcher/default_dispatcher.hpp"
#include "app/relay.hpp"

#include "common/awaitable_task_group.hpp"

#include "app/stats.hpp"
#include "app/request_load.hpp"
#include "app/dns/dns.hpp"
#include "common/session.hpp"
#include "common/rule.hpp"
#include "app/proxyman/outbound/handler.hpp"
#include "infra/config_types.hpp"
#include "infra/log.hpp"
#include "features/routing/router.hpp"
#include "sniff/sniffer.hpp"
#include "transport/link.hpp"
#include "transport/async_stream.hpp"
#include "transport/failure.hpp"
#include "common/buf/multi_buffer.hpp"

#include <algorithm>
#include <asio/experimental/awaitable_operators.hpp>
#include "transport/internet/async_delay.hpp"
#include <asio/this_coro.hpp>
#include <asio/use_awaitable.hpp>
#include <charconv>
#include <chrono>
#include <limits>
#include <new>
#include <string>
#include <stdexcept>
#include <vector>
#include <variant>

namespace app::dispatcher {

namespace {

void ApplySniffOverride(
    session::Context& ctx,
    const routing::SniffConfig& sniffing,
    const sniff::SniffResult& result) {
    if (!result.success) {
        return;
    }
    ctx.content.protocol.assign(result.protocol);
    if (result.domain.empty()) {
        return;
    }
    const std::string_view sniff_domain(result.domain.data(), result.domain.size());
    LOG_CONN_DEBUG(ctx, "sniffed protocol={} domain={}",
                   result.protocol, sniff_domain);
    if (sniffing.IsDomainExcluded(sniff_domain) ||
        !sniffing.MatchesDestOverride(result.protocol)) {
        return;
    }
    const uint16_t final_port = result.port > 0
        ? result.port
        : ctx.outbound.target.port;
    common::TargetAddress sniffed(sniff_domain, final_port);
    if (!sniffed.IsValid() || !sniffed.IsDomain()) {
        return;
    }
    if (sniffing.route_only) {
        ctx.outbound.route_target = std::move(sniffed);
    } else {
        ctx.outbound.route_target = {};
        ctx.outbound.original_target = std::move(ctx.outbound.target);
        ctx.outbound.target = std::move(sniffed);
    }
}

[[nodiscard]] RelayResult MakeRelayError(common::ErrorCode error) noexcept {
    RelayResult result;
    result.error = error;
    return result;
}

// Dispatch 顶层唯一的失败收尾，必须在 catch 处理块内调用：错误码只经
// ClassifyFailure 分类；请求取消且已有更具体的结果时保留原结果。
void FinishDispatchFailure(session::Context& ctx, StatsShard& stats,
                           RelayResult& result, const char* detail) noexcept {
    const common::ErrorCode error = transport::ClassifyFailure(
        std::current_exception(), common::ErrorCode::INTERNAL);
    if (error != common::ErrorCode::CANCELLED || result.error == common::ErrorCode::OK) {
        stats.OnError();
        result = MakeRelayError(error);
    }
    if (error == common::ErrorCode::CANCELLED || error == common::ErrorCode::SOCKET_EOF) return;
    try { LOG_CONN_WARN(ctx, "failed to process outbound traffic > {}", detail); }
    catch (...) {} // 日志不得越过分配失败边界。
}

std::chrono::seconds ResolveRelayIdleTimeout(
    const infra::TimeoutsConfig& timeouts,
    uint32_t pressure_idle_timeout) {
    auto idle_timeout = timeouts.IdleTimeout();
    if (pressure_idle_timeout > 0) {
        idle_timeout = std::min(
            idle_timeout, std::chrono::seconds(pressure_idle_timeout));
    }
    return idle_timeout;
}

net::awaitable<bool> SniffInitialPayload(
    net::io_context& io_context,
    const routing::SniffConfig& sniffing,
    transport::MultiBufferReader* inbound_reader,
    transport::AsyncStream* inbound_control,
    common::InitialPayload& first_packet,
    session::Context& ctx,
    StatsShard& stats,
    buf::MultiBufferBatch& outbound_first_payload,
    RelayResult& result,
    common::ErrorCode& cancellation_reason,
    const net::cancellation_state& sniff_cancellation) {
    using net::experimental::awaitable_operators::operator||;
    const bool datagram = ctx.content.network == common::Network::UDP;
    const size_t sniff_byte_limit = datagram ? 64 * 1024 : 4096;
    static constexpr size_t kSniffMaxDatagrams = 64;
    static constexpr auto kSniffWindow = std::chrono::milliseconds(200);
    buf::MultiBuffer sniff_payload;
    memory::ByteVector sniff_scratch;
    sniff::Sniffer sniffer;
    size_t cached_bytes = 0;
    size_t cached_datagrams = 0;

    auto copy_cached_bytes = [&](const buf::MultiBuffer& mb) {
        const size_t total = mb.byte_size();
        if (total == 0) {
            return std::span<const uint8_t>{};
        }
        const size_t want = std::min(total, sniff_byte_limit);
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
            return sniff::SniffResult{};
        }
        return sniffer.Sniff(sniff_data, ctx.content.network);
    };

    bool read_timed_out = false;
    auto consume_inbound_timeout = [&]() noexcept {
        if (!inbound_control) return false;
        const bool read_to = inbound_control->ConsumeReadTimeout();
        const bool idle_to = inbound_control->ConsumeIdleTimeout();
        return read_to || idle_to;
    };
    try {
        struct ReadResult {
            bool received = false;
            std::exception_ptr error;
        } read;
        // One frame per sniff read: the read, its EOF/timeout classification
        // and the capture of its failure for the timer race below.
        auto read_more = [&]() -> net::awaitable<void> {
            try {
                buf::MultiBuffer payload;
                try {
                    payload = co_await inbound_reader->ReadMultiBuffer();
                } catch (const IoSystemError& e) {
                    if (e.code() == net::error::eof && cached_bytes > 0) {
                        co_return;
                    }
                    throw;
                }
                if (payload.empty()) {
                    if (consume_inbound_timeout()) {
                        read_timed_out = true;
                        throw IoSystemError(net::error::timed_out);
                    }
                    co_return;
                }
                cached_bytes += payload.byte_size();
                ++cached_datagrams;
                if (datagram) {
                    sniff_payload = std::move(payload);
                } else {
                    sniff_payload.AppendAndCoalesce(std::move(payload));
                }
                read.received = true;
            } catch (...) {
                read.error = std::current_exception();
            }
        };
        const auto sniff_started = std::chrono::steady_clock::now();
        if (!first_packet.empty()) {
            sniff_payload = std::move(first_packet).MoveToMultiBuffer();
            cached_bytes = sniff_payload.byte_size();
            cached_datagrams = 1;
        }

        int no_clue_attempts = 0;
        for (;;) {
            if (!sniff_payload.empty()) {
                const auto sniffed = sniff_cached();
                if (datagram) {
                    // Keep each original read result intact. Only decrypted
                    // handshake fragments are combined inside the sniffer.
                    outbound_first_payload.Push(std::move(sniff_payload));
                }
                if (sniffed.success) {
                    ApplySniffOverride(ctx, sniffing, sniffed);
                    break;
                }
                if (datagram && !sniffed.need_more) {
                    break;
                }
                if (!sniffed.need_more) {
                    ++no_clue_attempts;
                    if (no_clue_attempts >= 2) {
                        break;
                    }
                }
                // Stop before another read once the inspection budget is
                // exhausted. Preserve an already-read final datagram even
                // when it crosses the byte limit (at most one UDP packet).
                if (cached_bytes >= sniff_byte_limit ||
                    (datagram && cached_datagrams >= kSniffMaxDatagrams)) {
                    break;
                }
            }
            const auto remaining = kSniffWindow -
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - sniff_started);
            if (remaining <= std::chrono::milliseconds::zero()) {
                break;
            }
            read = {};
            memory::ByteVector().swap(sniff_scratch);
            transport::internet::AsyncDelay delay(io_context);
            auto next = co_await (read_more() || delay.WaitFor(remaining));
            if (sniff_cancellation.cancelled() != net::cancellation_type::none) {
                throw IoSystemError(net::error::operation_aborted);
            }
            if (read.error) {
                if (next.index() == 0) std::rethrow_exception(read.error);
                try {
                    std::rethrow_exception(read.error);
                } catch (const IoSystemError& e) {
                    if (consume_inbound_timeout()) {
                        read_timed_out = true;
                        throw;
                    }
                    if (e.code() != net::error::operation_aborted) throw;
                }
            }
            if (!read.received) break;
        }
        if (!sniff_payload.empty()) {
            outbound_first_payload.Push(std::move(sniff_payload));
        }
    } catch (...) {
        // 分配失败交给 Dispatch 的统一收尾；其余失败经唯一分类入口取得错误码，
        // 再叠加本阶段的超时与请求取消语义。
        common::ErrorCode error = transport::ClassifyFailure(
            std::current_exception(), common::ErrorCode::SOCKET_READ_FAILED);
        if (error == common::ErrorCode::RESOURCE_EXHAUSTED) throw;
        if (read_timed_out || consume_inbound_timeout()) {
            error = common::ErrorCode::TIMEOUT;
        } else if (error == common::ErrorCode::CANCELLED &&
                   (cancellation_reason != common::ErrorCode::OK ||
                    sniff_cancellation.cancelled() != net::cancellation_type::none)) {
            throw;
        }
        stats.OnError();
        result = MakeRelayError(error);
        co_return false;
    }
    co_return true;
}

struct ActiveSessionScope {
    app::SessionTrackingState& session_tracking;
    app::SessionTrackingState::ActiveSession node{};

    ActiveSessionScope(session::Context& session_ctx,
                       app::SessionTrackingState& tracking)
        : session_tracking(tracking) {
        if (session_ctx.inbound.user_id > 0) {
            session_tracking.RegisterActiveSession(
                node,
                session_ctx.inbound.accounting_key,
                session_ctx.inbound.user_id,
                session_ctx.traffic);
        }
    }

    ~ActiveSessionScope() noexcept {
        session_tracking.UnregisterActiveSession(node);
    }
};

}  // namespace

DefaultDispatcher::DefaultDispatcher(
    const routing::Router& router,
    const proxyman::outbound::HandlerRegistry& outbound_handlers,
    rule::DetectRulePolicy& request_policy,
    app::SessionTrackingState& session_tracking,
    app::dns::DNS& dns_service,
    app::RequestLoadState& request_load) noexcept
    : router_(router)
    , outbound_handlers_(outbound_handlers)
    , request_policy_(request_policy)
    , session_tracking_(session_tracking)
    , dns_service_(dns_service)
    , request_load_(request_load) {}

net::awaitable<RelayResult> DefaultDispatcher::Dispatch(
    net::io_context& io_context,
    const routing::DispatchPolicy& policy,
    std::unique_ptr<transport::AsyncStream> inbound,
    transport::Link inbound_link,
    common::InitialPayload first_packet,
    session::Context& ctx,
    StatsShard& stats,
    const infra::TimeoutsConfig& timeouts) {
    app::RequestLoadState::DispatchScope load_scope(request_load_);
    const uint32_t pressure_idle_timeout = request_load_.PressureIdleTimeout();
    RelayResult result;
    common::ErrorCode cancellation_reason = common::ErrorCode::OK;
    try {
        co_await common::RunAwaitableTaskGroup(co_await net::this_coro::executor, [&](common::AwaitableTaskGroup& group) {
            group.Spawn(DispatchPreparedLink(
                io_context, policy, std::move(inbound), inbound_link,
                first_packet, ctx, stats, timeouts, pressure_idle_timeout,
                result, group, cancellation_reason));
        });
    } catch (const std::exception& e) {
        FinishDispatchFailure(ctx, stats, result, e.what());
    } catch (...) {
        FinishDispatchFailure(ctx, stats, result, "unknown error");
    }
    if (result.error == common::ErrorCode::CANCELLED && cancellation_reason != common::ErrorCode::OK) {
        result.error = cancellation_reason;
    }
    co_return result;
}

net::awaitable<void> DefaultDispatcher::DispatchPreparedLink(
    net::io_context& io_context,
    const routing::DispatchPolicy& policy,
    std::unique_ptr<transport::AsyncStream> inbound,
    transport::Link inbound_link,
    common::InitialPayload& first_packet,
    session::Context& ctx,
    StatsShard& stats,
    const infra::TimeoutsConfig& timeouts,
    uint32_t pressure_idle_timeout,
    RelayResult& result,
    common::AwaitableTaskGroup& request_group,
    common::ErrorCode& cancellation_reason) {

    struct RequestCancellation final : transport::CancellationSubscription {
        RequestCancellation(common::AwaitableTaskGroup& group, common::ErrorCode& reason) noexcept
            : group(group), reason(reason) {}
        common::AwaitableTaskGroup& group;
        common::ErrorCode& reason;

    private:
        void OnCancellation(transport::Cancellation event) noexcept override {
            reason = event.reason == common::ErrorCode::OK ? common::ErrorCode::CANCELLED : event.reason;
            group.Cancel();
        }
    } cancellation(request_group, cancellation_reason);
    auto* cancellation_reader = inbound_link.Valid() ? inbound_link.reader : inbound.get();
    if (cancellation_reader) {
        cancellation.Resubscribe(cancellation_reader->Cancellation());
    }
    if (cancellation_reason != common::ErrorCode::OK) {
        stats.OnError();
        result = MakeRelayError(cancellation_reason);
        co_return;
    }

    const bool has_protocol_link = inbound_link.Valid();
    if (!inbound && !has_protocol_link) {
        stats.OnError();
        result = MakeRelayError(common::ErrorCode::PROTOCOL_DECODE_FAILED);
        co_return;
    }
    transport::AsyncStream* inbound_endpoint = inbound.get();
    transport::MultiBufferReader* inbound_reader =
        has_protocol_link ? inbound_link.reader : inbound_endpoint;
    transport::MultiBufferWriter* inbound_writer =
        has_protocol_link ? inbound_link.writer : inbound_endpoint;
    transport::AsyncStream* inbound_control =
        inbound_link.control ? inbound_link.control : inbound_endpoint;
    if (inbound_control) {
        (void)inbound_control->ConsumePhaseDeadline();
        inbound_control->ClearPhaseDeadline();
    }

    if (!ctx.outbound.target.IsValid()) {
        stats.OnError();
        LOG_CONN_DEBUG(ctx, "rejected outbound request > invalid target");
        result = MakeRelayError(common::ErrorCode::PROTOCOL_DECODE_FAILED);
        co_return;
    }

    LOG_CONN_DEBUG(ctx, "protocol authenticated target={} email={}",
                   ctx.outbound.target, ctx.inbound.user_email);

    buf::MultiBufferBatch outbound_first_payload;
    const auto sniff_cancellation = co_await net::this_coro::cancellation_state;
    if (policy.sniffing.enabled && !policy.sniffing.metadata_only) {
        if (!co_await SniffInitialPayload(
                io_context, policy.sniffing, inbound_reader, inbound_control,
                first_packet, ctx, stats, outbound_first_payload, result,
                cancellation_reason, sniff_cancellation)) {
            co_return;
        }
    }
    if (sniff_cancellation.cancelled() != net::cancellation_type::none ||
        cancellation_reason != common::ErrorCode::OK) {
        throw IoSystemError(net::error::operation_aborted);
    }

    const common::TargetAddress& route_target = ctx.outbound.route_target.IsValid()
        ? ctx.outbound.route_target
        : ctx.outbound.target;
    // Only an unresolved domain under a resolving strategy can need DNS, and
    // IPIfNonMatch needs it only after the domain itself matched no rule.
    const auto strategy =
        detail::RequiresRouting(policy.outbound) && route_target.IsDomain() &&
                !route_target.resolved_addr
            ? router_.DomainStrategy()
            : routing::DomainStrategy::AsIs;
    std::optional<detail::OutboundSelection> selection;
    if (strategy != routing::DomainStrategy::IPOnDemand) {
        selection = SelectRoute(ctx, policy);
    }
    RouteResult dispatch =
        (selection && (strategy == routing::DomainStrategy::AsIs ||
                       selection->source != detail::SelectionSource::Fallback))
            ? FinishRoute(ctx, *selection)
            : co_await RouteAsync(ctx, policy, selection);
    auto outbound_handler = std::move(dispatch.handler);
    if (!outbound_handler) {
        if (dispatch.error == common::ErrorCode::BLOCKED) {
            LOG_CONN_WARN(ctx, "destination rejected source={}:{} target={} email={} > policy blocked",
                          ctx.inbound.source_ip, ctx.inbound.source_port,
                          ctx.outbound.target, ctx.inbound.user_email);
            if (ctx.inbound.user_id > 0 && ctx.outbound.target.IsValid()) {
                LOG_ACCESS(common::FormatAccessLog(ctx, common::AccessStatus::Rejected, "policy blocked"));
            }
            stats.OnError();
            result = MakeRelayError(common::ErrorCode::BLOCKED);
            co_return;
        }
        LOG_CONN_WARN(ctx, "failed to find outbound handler source={}:{} target={}",
                          ctx.inbound.source_ip, ctx.inbound.source_port, ctx.outbound.target);
        stats.OnError();
        result = MakeRelayError(common::ErrorCode::ROUTER_OUTBOUND_NOT_FOUND);
        co_return;
    }

    // UDP 与 TCP 共用主链路：dispatcher.Dispatch -> Handler.Dispatch ->
    // proxy::Outbound::Process（唯一一次动态分派）-> relay。

    // The handler's dialer reads the inbound local address from the session
    // (Xray: inbound connection local address); fill it from the control
    // stream when the ingress did not record one.
    if (!ctx.inbound.local_endpoint && inbound_control) {
        ctx.inbound.local_endpoint = inbound_control->LocalEndpoint();
    }
    const auto relay_idle_timeout = ResolveRelayIdleTimeout(
        timeouts, pressure_idle_timeout);
    if (pressure_idle_timeout > 0 &&
        relay_idle_timeout < timeouts.IdleTimeout()) {
        LOG_CONN_DEBUG(ctx,
                       "pressure mode reduced relay idle timeout from {}s to {}s",
                       timeouts.IdleTimeout().count(),
                       relay_idle_timeout.count());
    }
    const auto relay_write_timeout =
        std::min(timeouts.WriteTimeout(), relay_idle_timeout);
    if (inbound_control) {
        inbound_control->SetIdleTimeout(relay_idle_timeout);
        inbound_control->SetReadTimeout(std::chrono::seconds(0));
        inbound_control->SetWriteTimeout(relay_write_timeout);
    }

    RelayConfig relay_cfg;
    relay_cfg.idle_timeout  = relay_idle_timeout;
    relay_cfg.write_timeout = relay_write_timeout;
    relay_cfg.uplink_only   = timeouts.UplinkOnlyTimeout();
    relay_cfg.downlink_only = timeouts.DownlinkOnlyTimeout();
    relay_cfg.speed_limit   = ctx.content.speed_limit;

    if (outbound_first_payload.empty() && !first_packet.empty()) {
        outbound_first_payload.Push(std::move(first_packet).MoveToMultiBuffer());
    }
    first_packet = {};
    const size_t relay_payload_size = outbound_first_payload.byte_size();

    LOG_CONN_DEBUG(ctx, "relay started source={}:{} target={} payload={}B",
                   ctx.inbound.source_ip, ctx.inbound.source_port,
                   ctx.outbound.target, relay_payload_size);

    ActiveSessionScope relay_scope{ctx, session_tracking_};
    auto outbound_process = co_await outbound_handler->Dispatch(
        ctx,
        transport::Link{inbound_reader, inbound_writer, inbound_control},
        timeouts,
        stats,
        relay_cfg,
        std::move(outbound_first_payload));
    if (!outbound_process) {
        common::ErrorCode process_error = outbound_process.error();
        if (process_error == common::ErrorCode::OK) {
            process_error = common::ErrorCode::PROTOCOL_AUTH_FAILED;
        }
        if (process_error != common::ErrorCode::CANCELLED && process_error != common::ErrorCode::SOCKET_EOF &&
            process_error != common::ErrorCode::SOCKET_CLOSED && process_error != common::ErrorCode::CONNECTION_CLOSED) {
            LOG_CONN_WARN(ctx, "failed to process outbound traffic source={}:{} target={} > {}",
                          ctx.inbound.source_ip, ctx.inbound.source_port,
                          ctx.outbound.target, common::ErrorCodeToLogReason(process_error));
        }
        stats.OnError();
        result = MakeRelayError(process_error);
        co_return;
    }
    RelayResult relay_result = std::move(*outbound_process);

    if (relay_result.error != common::ErrorCode::OK) {
        LOG_CONN_DEBUG(ctx, "relay ended > {} up={}B down={}B closer={} target={}",
                       common::ErrorCodeToString(relay_result.error),
                       ctx.traffic.bytes_up, ctx.traffic.bytes_down,
                       relay_result.client_closed_first ? "client" : "target",
                       ctx.outbound.target);
    } else {
        LOG_CONN_DEBUG(ctx, "relay completed up={}B down={}B target={}",
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
    if (selection.source == detail::SelectionSource::Forced) {
        LOG_CONN_DEBUG(ctx, "selected fixed route target={}", ctx.outbound.target);
    } else {
        LOG_CONN_DEBUG(ctx, "selected route target={}", ctx.outbound.target);
    }

    if (request_policy_.Blocked(ctx)) {
        return RouteResult{
            .handler = {},
            .error = common::ErrorCode::BLOCKED,
        };
    }

    auto handler = outbound_handlers_.GetHandler(selection.outbound_tag);
    if (!handler) {
        return RouteResult{
            .handler = {},
            .error = common::ErrorCode::ROUTER_OUTBOUND_NOT_FOUND,
        };
    }

    return RouteResult{
        .handler = std::move(handler),
        .error = common::ErrorCode::OK,
    };
}

detail::OutboundSelection DefaultDispatcher::SelectRoute(
    session::Context& ctx,
    const routing::DispatchPolicy& policy) const {
    routing::RouteDecision decision;
    if (detail::RequiresRouting(policy.outbound)) {
        decision = router_.Route(ctx);
    }

    return detail::SelectOutbound(policy.outbound, decision);
}

// Entered only for an unresolved domain whose strategy needs DNS: IPOnDemand
// (no initial selection) or IPIfNonMatch after the domain fell back.
net::awaitable<DefaultDispatcher::RouteResult> DefaultDispatcher::RouteAsync(
    session::Context& ctx,
    const routing::DispatchPolicy& policy,
    std::optional<detail::OutboundSelection> initial_selection) {
    common::TargetAddress& route_target = ctx.outbound.route_target.IsValid()
        ? ctx.outbound.route_target
        : ctx.outbound.target;
    const bool sync_dial_target =
        &route_target == &ctx.outbound.target ||
        (ctx.outbound.target.IsDomain() &&
         domain::DnsHostnamesEqual(ctx.outbound.target.host, route_target.host));

    auto set_resolved_address = [&](const net::ip::address& addr) {
        route_target.resolved_addr = addr;
        if (sync_dial_target) {
            ctx.outbound.target.resolved_addr = addr;
        }
    };

    auto select_with_addresses =
        [&](const std::vector<net::ip::address>& addresses) -> detail::OutboundSelection {
            auto select_address = [&](const net::ip::address& addr) {
                set_resolved_address(addr);
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
            set_resolved_address(addresses.front());
            return last;
        };

    auto dns_result = co_await dns_service_.Resolve(route_target.host);
    // DNS may return a failed result after cancellation. Do not publish that
    // result into the request or continue to route/outbound lookup.
    const auto cancellation = co_await net::this_coro::cancellation_state;
    if (cancellation.cancelled() != net::cancellation_type::none)
        throw IoSystemError(net::error::operation_aborted);
    if (!dns_result.Ok()) {
        LOG_CONN_DEBUG(ctx, "routing DNS lookup failed target={} > {}: {}",
                       route_target.host, common::ErrorCodeToString(dns_result.error), dns_result.error_msg);
    } else if (!dns_result.addresses.empty()) {
        co_return FinishRoute(ctx, select_with_addresses(dns_result.addresses));
    }
    co_return FinishRoute(
        ctx,
        initial_selection ? *initial_selection : SelectRoute(ctx, policy));
}

}  // namespace app::dispatcher
