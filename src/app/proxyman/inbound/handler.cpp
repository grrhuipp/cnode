#include "acppnode/app/proxyman/inbound/handler.hpp"
#include "acppnode/common/ip_address.hpp"

#include "acppnode/app/request_load_state.hpp"

#include "acppnode/app/rate_limiter.hpp"
#include "acppnode/common/allocator.hpp"
#include "acppnode/common/ip_utils.hpp"
#include "acppnode/common/session.hpp"
#include "acppnode/infra/config_types.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/proxy/inbound.hpp"
#include "acppnode/transport/internet/proxy_protocol.hpp"
#include "acppnode/transport/internet/transport_stack.hpp"
#include "acppnode/transport/link_error.hpp"

#include <exception>
#include <new>

namespace acpp::proxyman::inbound {

namespace {

std::string_view RealIpHeader(const StreamSettings& settings) noexcept {
    if (settings.IsWs()) return settings.ws.real_ip_header;
    if (settings.IsHttpUpgrade()) return settings.http_upgrade.real_ip_header;
    if (settings.IsHttp()) return settings.http.real_ip_header;
    return {};
}

void ApplyHttpRealIp(
    session::Context& ctx,
    std::string_view real_ip) {
    if (real_ip.empty()) return;
    const auto literal = iputil::ParseLiteral(real_ip);
    if (!literal) return;
    const auto address = iputil::NormalizeAddress(*literal);
    ctx.inbound.source_addr = address;
    ctx.inbound.source_ip = iputil::AddressText(address).View();
    // Forwarded address headers do not reliably carry the original client
    // port. Zero is explicit unknown; retaining the CDN port is a false tuple.
    ctx.inbound.source_port = 0;
    ctx.inbound.client_ip_source = "http_header";
}

void ApplyProxyProtocolResult(
    session::Context& ctx,
    const ProxyProtocolResult& result) {
    if (!result.success() || !result.src_addr) {
        return;
    }

    const auto proxy_ip = std::move(ctx.inbound.source_ip);
    ctx.inbound.source_addr = *result.src_addr;
    ctx.inbound.source_ip = iputil::AddressText(*result.src_addr).View();

    ctx.inbound.source_port = result.src_port;
    ctx.inbound.client_ip_source = "proxy_protocol";
    LOG_CONN_DEBUG(
        ctx,
        "[{}] PROXY protocol: proxy={} real_ip={}:{}",
        ctx.inbound.tag,
        proxy_ip,
        ctx.inbound.source_ip,
        ctx.inbound.source_port);
}


class ConnectionStatsScope {
public:
    explicit ConnectionStatsScope(StatsShard& stats) noexcept
        : stats_(&stats) {
        stats_->OnConnectionAccepted();
    }

    ~ConnectionStatsScope() noexcept {
        if (stats_) {
            stats_->OnConnectionClosed();
        }
    }

    ConnectionStatsScope(const ConnectionStatsScope&) = delete;
    ConnectionStatsScope& operator=(const ConnectionStatsScope&) = delete;
    ConnectionStatsScope(ConnectionStatsScope&&) = delete;
    ConnectionStatsScope& operator=(ConnectionStatsScope&&) = delete;

private:
    StatsShard* stats_;
};

// 物理连接与逻辑子流共用的协议处理收尾：Process 自身已分类上报结果，
// 这里只把逃逸的异常收敛为一次错误统计，非预期异常额外记录。
net::awaitable<void> RunInboundProxy(
    Inbound& proxy,
    std::unique_ptr<AsyncStream> stream,
    routing::Dispatcher& dispatcher,
    const inbound::ReceiverSettings& listener,
    net::io_context& io_context,
    session::Context& ctx,
    const TimeoutsConfig& timeouts,
    uint32_t pressure_idle_timeout,
    StatsShard& stats) {
    try {
        (void)co_await proxy.Process(
            std::move(stream),
            dispatcher,
            listener,
            io_context,
            ctx,
            timeouts,
            pressure_idle_timeout);
    } catch (const transport::LinkError&) {
        stats.OnError();
    } catch (const std::bad_alloc&) {
        stats.OnError();
    } catch (const IoSystemError&) {
        stats.OnError();
    } catch (const std::exception& e) {
        LOG_CONN_WARN(ctx, "[Session] inbound process exception: {}", e.what());
        stats.OnError();
    } catch (...) {
        LOG_CONN_WARN(ctx, "[Session] inbound process exception: unknown");
        stats.OnError();
    }
}

}  // namespace

class Handler::LogicalTransportStreamSink final
    : public InboundTransportStreamHandler {
public:
    LogicalTransportStreamSink(std::shared_ptr<Handler> handler,
                               net::io_context& io_context,
                               routing::Dispatcher& dispatcher,
                               StatsShard& stats,
                               app::RequestLoadState& request_load,
                               const TimeoutsConfig& timeouts,
                               const session::Context& base_ctx,
                               InboundTransportMetadata metadata,
                               std::shared_ptr<ConnectionLimiter::Family> family)
        : handler_(std::move(handler))
        , io_context_(io_context)
        , dispatcher_(dispatcher)
        , stats_(stats)
        , request_load_(request_load)
        , timeouts_(timeouts)
        , metadata_(std::move(metadata))
        , family_(std::move(family)) {
        base_ctx_.InitSubstreamFrom(base_ctx);
        base_ctx_.conn_id = base_ctx.conn_id;
        base_ctx_.accept_time_us = base_ctx.accept_time_us;
        base_ctx_.inbound.user_id = 0;
        base_ctx_.inbound.user_email.clear();
    }

    [[nodiscard]] InboundTransportMetadata& Metadata() noexcept {
        return metadata_;
    }

    void OnInboundTransportReady(AsyncStream& stream) override {
        if (stream.ConsumePhaseDeadline()) {
            throw transport::LinkError(ErrorCode::TIMEOUT);
        }
        stream.ClearPhaseDeadline();
        stream.SetIdleTimeout(timeouts_.IdleTimeout());
    }

    void OnInboundTransportRequest(AsyncStream& stream) override {
        stream.SetIdleTimeout(timeouts_.HandshakeTimeout());
        (void)stream.StartPhaseDeadline(timeouts_.HandshakeTimeout());
    }

    net::awaitable<void> OnInboundTransportStream(
        std::unique_ptr<AsyncStream> stream,
        InboundTransportMetadata metadata) override {
        if (!stream) {
            co_return;
        }
        session::Context ctx;
        ctx.InitSubstreamFrom(base_ctx_);
        ApplyHttpRealIp(ctx, metadata.real_ip);
        co_await handler_->ProcessPreparedTransportStream(
            io_context_, dispatcher_, stats_, request_load_, timeouts_,
            std::move(stream), ctx, family_);
    }

private:
    std::shared_ptr<Handler> handler_;
    net::io_context& io_context_;
    routing::Dispatcher& dispatcher_;
    StatsShard& stats_;
    app::RequestLoadState& request_load_;
    TimeoutsConfig timeouts_;
    session::Context base_ctx_;
    InboundTransportMetadata metadata_;
    std::shared_ptr<ConnectionLimiter::Family> family_;
};

Handler::Handler(inbound::ReceiverSettings receiver, std::unique_ptr<Inbound> proxy,
                 ConnectionLimiter& limiter)
    : receiver_(std::move(receiver))
    , security_(receiver_.stream_settings, StreamEndpointRole::Inbound)
    , proxy_(std::move(proxy))
    , limiter_(limiter) {}

Handler::Handler(inbound::ReceiverSettings receiver, ProtocolProvider& provider,
                 ConnectionLimiter& limiter)
    : receiver_(std::move(receiver))
    , security_(receiver_.stream_settings, StreamEndpointRole::Inbound)
    , provider_(&provider)
    , limiter_(limiter) {}

net::awaitable<void> Handler::ProcessPreparedTransportStream(
    net::io_context& io_context,
    routing::Dispatcher& dispatcher,
    StatsShard& stats,
    app::RequestLoadState& request_load,
    const TimeoutsConfig& timeouts,
    std::unique_ptr<AsyncStream> stream,
    session::Context& ctx,
    const std::shared_ptr<ConnectionLimiter::Family>& family) {
    const inbound::ReceiverSettings& listener = receiver_;
    ConnectionStatsScope connection_stats(stats);

    ctx.inbound.accounting_key.assign(listener.accounting_key);

    if (!stream) {
        stats.OnError();
        co_return;
    }

    auto admission = co_await limiter_.ReserveLogical(
        family, ctx.inbound.tag, ctx.inbound.source_ip,
        ctx.inbound.HasProxyProtocolClientIP());
    const auto reject = admission.reason;
    if (reject != ConnectionLimiter::RejectReason::NONE) {
        LOG_CONN_DEBUG(ctx, "rejected conn_limit src={}:{} reason={}",
                       ctx.inbound.source_ip, ctx.inbound.source_port,
                       ConnectionLimiter::RejectReasonToString(reject));
        stats.OnError();
        co_return;
    }
    auto connection_limit = std::move(admission.reservation);

    (void)stream->StartPhaseDeadline(timeouts.HandshakeTimeout());

    LOG_CONN_DEBUG(ctx, "[Session] Logical transport stream ready ({}/{})",
                   listener.stream_settings.security,
                   listener.stream_settings.network);

    if (!proxy_ && !provider_) {
        stats.OnError();
        co_return;
    }
    co_await RunInboundProxy(
        proxy_ ? *proxy_ : provider_->GetProxy(),
        std::move(stream), dispatcher, listener, io_context, ctx, timeouts,
        request_load.PressureIdleTimeout(), stats);
}

net::awaitable<void> Handler::ProcessAcceptedTCP(
    net::io_context& io_context,
    routing::Dispatcher& dispatcher,
    StatsShard& stats,
    app::RequestLoadState& request_load,
    const TimeoutsConfig& timeouts,
    std::unique_ptr<AsyncStream> raw_conn,
    session::Context& ctx,
    app::dns::DNS* dns_service) {
    const inbound::ReceiverSettings& listener = receiver_;
    ConnectionStatsScope connection_stats(stats);

    ctx.inbound.accounting_key.assign(listener.accounting_key);

    if (!raw_conn) {
        stats.OnError();
        co_return;
    }

    if (listener.proxy_protocol != ProxyProtocolMode::Off) {
        auto proxy_read = co_await ReadInboundProxyProtocol(
            *raw_conn,
            timeouts.HandshakeTimeout());
        if (!proxy_read.ok()) {
            switch (proxy_read.status) {
                case ProxyProtocolReadStatus::TimedOut:
                    LOG_CONN_WARN(
                        ctx,
                        "failed to read PROXY protocol client={} > i/o timeout",
                        ctx.inbound.source_ip);
                    break;
                case ProxyProtocolReadStatus::Truncated:
                    LOG_CONN_WARN(ctx, "failed to read PROXY protocol > truncated header");
                    break;
                case ProxyProtocolReadStatus::TooLarge:
                    LOG_CONN_WARN(
                        ctx,
                        "failed to read PROXY protocol > header too large limit={}B",
                        kProxyHeaderMaxBytes);
                    break;
                case ProxyProtocolReadStatus::Invalid:
                    LOG_CONN_WARN(ctx, "failed to read PROXY protocol > invalid header");
                    break;
                case ProxyProtocolReadStatus::Ok:
                    break;
            }
            stats.OnError();
            raw_conn->CloseAbortive();
            co_return;
        }

        if (listener.proxy_protocol == ProxyProtocolMode::On &&
            !proxy_read.result.success()) {
            LOG_CONN_WARN(
                ctx,
                "failed to read PROXY protocol client={} > required header missing",
                ctx.inbound.source_ip);
            stats.OnError();
            raw_conn->CloseAbortive();
            co_return;
        }

        ApplyProxyProtocolResult(ctx, proxy_read.result);
    }

    if (ctx.inbound.HasProxyProtocolClientIP() &&
        co_await limiter_.IsBanned(ctx.inbound.tag, ctx.inbound.source_ip)) {
        LOG_CONN_DEBUG(ctx, "rejected ip_banned (early) src={}:{}",
                       ctx.inbound.source_ip, ctx.inbound.source_port);
        stats.OnError();
        co_return;
    }

    auto physical_admission = co_await limiter_.ReservePhysical();
    auto reject = physical_admission.reason;
    if (reject != ConnectionLimiter::RejectReason::NONE) {
        LOG_CONN_DEBUG(ctx, "rejected conn_limit src={}:{} reason={}",
                       ctx.inbound.source_ip, ctx.inbound.source_port,
                       ConnectionLimiter::RejectReasonToString(reject));
        stats.OnError();
        co_return;
    }
    auto connection_limit = std::move(physical_admission.reservation);

    raw_conn->SetIdleTimeout(timeouts.HandshakeTimeout());
    (void)raw_conn->StartPhaseDeadline(timeouts.HandshakeTimeout());

    LOG_CONN_DEBUG(ctx, "[Session] Building transport ({}/{})",
                   listener.stream_settings.security,
                   listener.stream_settings.network);

    InboundTransportMetadata local_metadata;
    local_metadata.real_ip_header.assign(RealIpHeader(listener.stream_settings));
    InboundTransportMetadata* transport_metadata = &local_metadata;
    std::shared_ptr<LogicalTransportStreamSink> logical_stream_handler;
    if (listener.stream_settings.IsGrpc() ||
        listener.stream_settings.IsHttp() ||
        listener.stream_settings.IsXHttp()) {
        logical_stream_handler = memory::AllocateShared<LogicalTransportStreamSink>(
            shared_from_this(),
            io_context,
            dispatcher,
            stats,
            request_load,
            timeouts,
            ctx,
            std::move(local_metadata), connection_limit.FamilyLease());
        transport_metadata = &logical_stream_handler->Metadata();
    }
    // HTTP/1 handshakes drop their sink reference before returning the
    // stream; keep the sink that owns the extracted metadata until read.
    auto metadata_owner = logical_stream_handler;

    auto build_result = co_await BuildInboundTransport(
        io_context,
        std::move(raw_conn),
        listener.stream_settings,
        security_.Context(),
        ctx.conn_id,
        std::move(logical_stream_handler),
        transport_metadata,
        dns_service);
    if (!build_result) {
        LOG_CONN_DEBUG(ctx, "[Session] Transport handshake failed ({}/{})",
                       listener.stream_settings.security,
                       listener.stream_settings.network);
        stats.OnError();
        co_return;
    }
    auto stream = std::move(*build_result);
    if (!stream) {
        LOG_CONN_DEBUG(ctx, "[Session] Transport consumed connection ({}/{})",
                       listener.stream_settings.security,
                       listener.stream_settings.network);
        co_return;
    }

    if (!transport_metadata->real_ip.empty()) {
        LOG_CONN_DEBUG(ctx, "[Session] HTTP transport real IP from header: {} -> {}",
                       ctx.inbound.source_ip, transport_metadata->real_ip);
        ApplyHttpRealIp(ctx, transport_metadata->real_ip);
    }

    metadata_owner.reset();
    local_metadata = {};
    auto ip_admission = co_await limiter_.ReserveIP(
        ctx.inbound.tag, ctx.inbound.source_ip,
        ctx.inbound.HasProxyProtocolClientIP());
    reject = ip_admission.reason;
    if (reject != ConnectionLimiter::RejectReason::NONE) {
        LOG_CONN_DEBUG(ctx, "rejected conn_limit src={}:{} reason={}",
                       ctx.inbound.source_ip, ctx.inbound.source_port,
                       ConnectionLimiter::RejectReasonToString(reject));
        stats.OnError();
        co_return;
    }
    auto ip_limit = std::move(ip_admission.reservation);

    LOG_CONN_DEBUG(ctx, "[Session] Transport ready ({}/{})",
                   listener.stream_settings.security,
                   listener.stream_settings.network);

    if (!proxy_ && !provider_) {
        stats.OnError();
        co_return;
    }
    co_await RunInboundProxy(
        proxy_ ? *proxy_ : provider_->GetProxy(),
        std::move(stream), dispatcher, listener, io_context, ctx, timeouts,
        request_load.PressureIdleTimeout(), stats);
}

}  // namespace acpp::proxyman::inbound
