#include "acppnode/app/proxyman/inbound/handler.hpp"

#include "acppnode/app/access_log_session.hpp"
#include "acppnode/app/request_load_state.hpp"

#include "acppnode/app/rate_limiter.hpp"
#include "acppnode/common/allocator.hpp"
#include "acppnode/common/ip_utils.hpp"
#include "acppnode/common/read_prefix_capture.hpp"
#include "acppnode/common/session.hpp"
#include "acppnode/infra/config_types.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/proxy/inbound.hpp"
#include "acppnode/transport/internet/transport_stack.hpp"

#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <exception>
#include <optional>

namespace acpp::proxyman::inbound {

namespace {

std::string_view RealIpHeader(const StreamSettings& settings) noexcept {
    if (settings.IsWs()) return settings.ws.real_ip_header;
    if (settings.IsHttpUpgrade()) return settings.http_upgrade.real_ip_header;
    if (settings.IsHttp()) return settings.http.real_ip_header;
    return {};
}

std::string TransportRouteId(const StreamSettings& settings) {
    if (settings.IsWs()) return settings.ws.path;
    if (settings.IsHttpUpgrade()) return settings.http_upgrade.path;
    if (settings.IsHttp()) return settings.http.path;
    if (settings.IsGrpc()) return settings.grpc.RequestPath();
    if (settings.IsXHttp()) return settings.xhttp.NormalizedPath();
    return {};
}

std::string ConfiguredHttpHost(const StreamSettings& settings) {
    if (settings.IsHttpUpgrade()) return settings.http_upgrade.host;
    if (settings.IsHttp()) return settings.http.host;
    if (settings.IsGrpc()) return settings.grpc.authority;
    if (settings.IsXHttp()) return settings.xhttp.host;
    return {};
}

void PrepareInboundLogMetadata(
    session::Context& ctx,
    const ReceiverSettings& listener) {
    ctx.inbound.transport = listener.stream_settings.network;
    ctx.inbound.security = listener.stream_settings.security;
    ctx.inbound.transport_route_id = TransportRouteId(listener.stream_settings);
    ctx.inbound.http_host = ConfiguredHttpHost(listener.stream_settings);
}

void ApplyHttpRealIp(
    session::Context& ctx,
    std::string_view real_ip,
    std::string_view header) {
    if (real_ip.empty()) return;
    IoErrorCode ec;
    auto address = net::ip::make_address(real_ip, ec);
    if (ec) return;
    address = iputil::NormalizeAddress(address);
    ctx.inbound.source_addr = address;
    ctx.inbound.source_ip = address.to_string();
    // Forwarded address headers do not reliably carry the original client
    // port. Zero is explicit unknown; retaining the CDN port is a false tuple.
    ctx.inbound.source_port = 0;
    ctx.inbound.client_ip_source = header.empty()
        ? std::string("http_header")
        : std::string("http_header:") + std::string(header);
    ctx.inbound.client_ip_trusted = true;
}

class ConnectionLimitScope {
public:
    ConnectionLimitScope(ConnectionLimiterPtr limiter, std::string_view ip)
        : limiter_(limiter), ip_(ip) {}

    ~ConnectionLimitScope() noexcept {
        if (!limiter_) {
            return;
        }
        try {
            if (ip_accepted_) {
                limiter_->Release(ip_);
            } else {
                limiter_->ReleaseGlobal();
            }
        } catch (...) {
        }
    }

    ConnectionLimitScope(const ConnectionLimitScope&) = delete;
    ConnectionLimitScope& operator=(const ConnectionLimitScope&) = delete;
    ConnectionLimitScope(ConnectionLimitScope&&) = delete;
    ConnectionLimitScope& operator=(ConnectionLimitScope&&) = delete;

    void UpdateIP(std::string_view ip) {
        ip_.assign(ip.data(), ip.size());
    }

    void MarkIPAccepted() noexcept {
        ip_accepted_ = true;
    }

private:
    ConnectionLimiterPtr limiter_;
    memory::ThreadLocalString ip_;
    bool ip_accepted_ = false;
};

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

void CopyTransportBaseContext(const session::Context& source,
                              session::Context& target) {
    target.conn_id = session::NewID(source.worker_id);
    target.worker_id = source.worker_id;
    target.accept_time_us = NowMicros();
    target.parent_conn_id = source.conn_id;
    target.stream_id = target.conn_id;
    target.runtime_generation = source.runtime_generation;
    target.config_generation = source.config_generation;
    target.inbound = source.inbound;
    target.inbound.user_id = 0;
    target.inbound.user_email.clear();
    target.sockopt = source.sockopt;
}

class LogicalTransportStreamSink final
    : public InboundTransportStreamHandler
    , public std::enable_shared_from_this<LogicalTransportStreamSink> {
public:
    LogicalTransportStreamSink(std::shared_ptr<Handler> handler,
                               net::io_context& io_context,
                               routing::Dispatcher& dispatcher,
                               StatsShard& stats,
                               app::RequestLoadState& request_load,
                               const TimeoutsConfig& timeouts,
                               const session::Context& base_ctx,
                               std::shared_ptr<InboundTransportMetadata> metadata,
                               int64_t transport_started_at_us)
        : handler_(std::move(handler))
        , io_context_(io_context)
        , dispatcher_(dispatcher)
        , stats_(stats)
        , request_load_(request_load)
        , timeouts_(timeouts)
        , metadata_(std::move(metadata))
        , transport_started_at_us_(transport_started_at_us) {
        CopyTransportBaseContext(base_ctx, base_ctx_);
        base_ctx_.conn_id = base_ctx.conn_id;
        base_ctx_.accept_time_us = base_ctx.accept_time_us;
    }

    void OnInboundTransportStream(std::unique_ptr<AsyncStream> stream) override {
        if (!stream) {
            return;
        }
        auto self = shared_from_this();
        net::co_spawn(
            io_context_.get_executor(),
            [self, stream = std::move(stream)]() mutable -> net::awaitable<void> {
                session::Context ctx;
                CopyTransportBaseContext(self->base_ctx_, ctx);
                if (self->metadata_) {
                    ctx.inbound.tls_sni = self->metadata_->tls_sni;
                    ctx.inbound.tls_alpn = self->metadata_->tls_alpn;
                    ctx.inbound.tls_version = self->metadata_->tls_version;
                    ctx.inbound.tls_fingerprint = self->metadata_->tls_fingerprint;
                    if (!self->metadata_->http_host.empty()) {
                        ctx.inbound.http_host = self->metadata_->http_host;
                    }
                    ApplyHttpRealIp(
                        ctx,
                        self->metadata_->real_ip,
                        self->metadata_->real_ip_header);
                }
                const int64_t transport_ready_at_us = NowMicros();
                ctx.inbound.transport_ready_at_unix_us = transport_ready_at_us;
                if (transport_ready_at_us > self->transport_started_at_us_) {
                    ctx.inbound.transport_handshake_ms = static_cast<uint64_t>(
                        (transport_ready_at_us - self->transport_started_at_us_) / 1000);
                }
                co_await self->handler_->ProcessPreparedTransportStream(
                    self->io_context_,
                    self->dispatcher_,
                    self->stats_,
                    self->request_load_,
                    self->timeouts_,
                    std::move(stream),
                    ctx);
            },
            net::detached);
    }

private:
    std::shared_ptr<Handler> handler_;
    net::io_context& io_context_;
    routing::Dispatcher& dispatcher_;
    StatsShard& stats_;
    app::RequestLoadState& request_load_;
    TimeoutsConfig timeouts_;
    session::Context base_ctx_;
    std::shared_ptr<InboundTransportMetadata> metadata_;
    int64_t transport_started_at_us_ = 0;
};

}  // namespace

Handler::Handler(inbound::ReceiverSettings receiver, std::unique_ptr<Inbound> proxy)
    : receiver_(std::move(receiver))
    , proxy_(std::move(proxy)) {}

net::awaitable<void> Handler::ProcessPreparedTransportStream(
    net::io_context& io_context,
    routing::Dispatcher& dispatcher,
    StatsShard& stats,
    app::RequestLoadState& request_load,
    const TimeoutsConfig& timeouts,
    std::unique_ptr<AsyncStream> stream,
    session::Context& ctx) {
    const inbound::ReceiverSettings& listener = receiver_;
    ConnectionStatsScope connection_stats(stats);

    ctx.inbound.access_source_ref = listener.access_source_ref;
    ctx.inbound.protocol = listener.protocol;
    PrepareInboundLogMetadata(ctx, listener);
    app::AccessLogSession access_log(ctx);

    ctx.inbound.read_prefix_capture = std::make_shared<ReadPrefixCapture>();
    if (stream) {
        stream->SetReadPrefixCapture(ctx.inbound.read_prefix_capture);
    }

    if (!stream) {
        stats.OnError();
        access_log.Fail(ErrorCode::PROTOCOL_DECODE_FAILED);
        co_return;
    }

    if (listener.limiter &&
        listener.limiter->GetLimiter().IsBanned(ctx.inbound.tag, ctx.inbound.source_ip)) {
        LOG_CONN_DEBUG(ctx, "rejected ip_banned (logical) src={}:{}",
                       ctx.inbound.source_ip, ctx.inbound.source_port);
        stats.OnError();
        access_log.Fail(ErrorCode::BLOCKED);
        co_return;
    }

    std::optional<ConnectionLimitScope> connection_limit;
    if (listener.limiter) {
        auto reject = listener.limiter->TryAcceptGlobal();
        if (reject != ConnectionLimiter::RejectReason::NONE) {
            LOG_CONN_DEBUG(ctx, "rejected conn_limit src={}:{} reason={}",
                           ctx.inbound.source_ip, ctx.inbound.source_port,
                           ConnectionLimiter::RejectReasonToString(reject));
            stats.OnError();
            access_log.Fail(ErrorCode::CONNECTION_LIMITED);
            co_return;
        }
        connection_limit.emplace(listener.limiter, ctx.inbound.source_ip);
        reject = listener.limiter->TryAcceptIP(ctx.inbound.tag, ctx.inbound.source_ip);
        if (reject != ConnectionLimiter::RejectReason::NONE) {
            LOG_CONN_DEBUG(ctx, "rejected conn_limit src={}:{} reason={}",
                           ctx.inbound.source_ip, ctx.inbound.source_port,
                           ConnectionLimiter::RejectReasonToString(reject));
            stats.OnError();
            access_log.Fail(ErrorCode::CONNECTION_LIMITED);
            co_return;
        }
        connection_limit->MarkIPAccepted();
    }

    stream->SetStreamLabel("in");
    stream->SetIdleTimeout(timeouts.HandshakeTimeout());
    (void)stream->StartPhaseDeadline(timeouts.HandshakeTimeout());

    LOG_CONN_DEBUG(ctx, "[Session] Logical transport stream ready ({}/{})",
                   listener.stream_settings.security,
                   listener.stream_settings.network);

    if (!proxy_) {
        stats.OnError();
        access_log.Fail(ErrorCode::INTERNAL);
        co_return;
    }
    try {
        auto relay_result = co_await proxy_->Process(
            std::move(stream),
            dispatcher,
            listener,
            io_context,
            ctx,
            timeouts,
            request_load.PressureIdleTimeout());
        access_log.Complete(relay_result);
    } catch (const std::exception& e) {
        LOG_CONN_WARN(ctx, "[Session] logical inbound process exception: {}", e.what());
        stats.OnError();
        access_log.Fail(ErrorCode::INTERNAL);
    } catch (...) {
        LOG_CONN_WARN(ctx, "[Session] logical inbound process exception: unknown");
        stats.OnError();
        access_log.Fail(ErrorCode::INTERNAL);
    }
}

net::awaitable<void> Handler::ProcessAcceptedTCP(
    net::io_context& io_context,
    routing::Dispatcher& dispatcher,
    StatsShard& stats,
    app::RequestLoadState& request_load,
    const TimeoutsConfig& timeouts,
    std::unique_ptr<AsyncStream> raw_conn,
    session::Context& ctx) {
    const inbound::ReceiverSettings& listener = receiver_;
    ConnectionStatsScope connection_stats(stats);

    ctx.inbound.access_source_ref = listener.access_source_ref;
    ctx.inbound.protocol = listener.protocol;
    PrepareInboundLogMetadata(ctx, listener);
    app::AccessLogSession access_log(ctx);

    ctx.inbound.read_prefix_capture = std::make_shared<ReadPrefixCapture>();
    if (raw_conn) {
        raw_conn->SetReadPrefixCapture(ctx.inbound.read_prefix_capture);
    }

    if (listener.limiter &&
        listener.limiter->GetLimiter().IsBanned(ctx.inbound.tag, ctx.inbound.source_ip)) {
        LOG_CONN_DEBUG(ctx, "rejected ip_banned (early) src={}:{}",
                       ctx.inbound.source_ip, ctx.inbound.source_port);
        stats.OnError();
        access_log.Fail(ErrorCode::BLOCKED);
        co_return;
    }

    std::optional<ConnectionLimitScope> connection_limit;
    if (listener.limiter) {
        auto reject = listener.limiter->TryAcceptGlobal();
        if (reject != ConnectionLimiter::RejectReason::NONE) {
            LOG_CONN_DEBUG(ctx, "rejected conn_limit src={}:{} reason={}",
                           ctx.inbound.source_ip, ctx.inbound.source_port,
                           ConnectionLimiter::RejectReasonToString(reject));
            stats.OnError();
            access_log.Fail(ErrorCode::CONNECTION_LIMITED);
            co_return;
        }
        connection_limit.emplace(listener.limiter, ctx.inbound.source_ip);
    }

    raw_conn->SetStreamLabel("in");
    raw_conn->SetIdleTimeout(timeouts.HandshakeTimeout());
    (void)raw_conn->StartPhaseDeadline(timeouts.HandshakeTimeout());

    LOG_CONN_DEBUG(ctx, "[Session] Building transport ({}/{})",
                   listener.stream_settings.security,
                   listener.stream_settings.network);

    const int64_t transport_started_at_us = NowMicros();
    auto transport_metadata = std::make_shared<InboundTransportMetadata>();
    transport_metadata->real_ip_header =
        std::string(RealIpHeader(listener.stream_settings));
    std::shared_ptr<InboundTransportStreamHandler> logical_stream_handler;
    if (listener.stream_settings.IsGrpc() ||
        listener.stream_settings.IsHttp() ||
        listener.stream_settings.IsXHttp()) {
        logical_stream_handler = std::make_shared<LogicalTransportStreamSink>(
            shared_from_this(),
            io_context,
            dispatcher,
            stats,
            request_load,
            timeouts,
            ctx,
            transport_metadata,
            transport_started_at_us);
    }

    std::string ws_real_ip;
    auto build_result = co_await BuildInboundTransport(
        io_context,
        std::move(raw_conn), listener.stream_settings,
        listener.stream_settings.NeedsHttpRealIpExtraction() ? &ws_real_ip : nullptr,
        ctx.conn_id,
        std::move(logical_stream_handler),
        transport_metadata.get());
    const int64_t transport_ended_at_us = NowMicros();
    if (transport_ended_at_us > transport_started_at_us) {
        ctx.inbound.transport_handshake_ms = static_cast<uint64_t>(
            (transport_ended_at_us - transport_started_at_us) / 1000);
    }
    ctx.inbound.transport_ready_at_unix_us = transport_ended_at_us;
    ctx.inbound.tls_sni = transport_metadata->tls_sni;
    ctx.inbound.tls_alpn = transport_metadata->tls_alpn;
    ctx.inbound.tls_version = transport_metadata->tls_version;
    ctx.inbound.tls_fingerprint = transport_metadata->tls_fingerprint;
    if (!transport_metadata->http_host.empty()) {
        ctx.inbound.http_host = transport_metadata->http_host;
    }

    if (!build_result) {
        LOG_CONN_DEBUG(ctx, "[Session] Transport handshake failed ({}/{})",
                       listener.stream_settings.security,
                       listener.stream_settings.network);
        stats.OnError();
        access_log.Fail(build_result.error());
        co_return;
    }
    auto stream = std::move(*build_result);
    if (!stream) {
        LOG_CONN_DEBUG(ctx, "[Session] Transport consumed connection ({}/{})",
                       listener.stream_settings.security,
                       listener.stream_settings.network);
        access_log.Suppress();
        co_return;
    }

    if (!ws_real_ip.empty()) {
        LOG_CONN_DEBUG(ctx, "[Session] HTTP transport real IP from header: {} -> {}",
                       ctx.inbound.source_ip, ws_real_ip);
        ApplyHttpRealIp(
            ctx, ws_real_ip, RealIpHeader(listener.stream_settings));
    }

    if (connection_limit && listener.limiter) {
        connection_limit->UpdateIP(ctx.inbound.source_ip);
        auto reject = listener.limiter->TryAcceptIP(ctx.inbound.tag, ctx.inbound.source_ip);
        if (reject != ConnectionLimiter::RejectReason::NONE) {
            LOG_CONN_DEBUG(ctx, "rejected conn_limit src={}:{} reason={}",
                           ctx.inbound.source_ip, ctx.inbound.source_port,
                           ConnectionLimiter::RejectReasonToString(reject));
            stats.OnError();
            access_log.Fail(ErrorCode::CONNECTION_LIMITED);
            co_return;
        }
        connection_limit->MarkIPAccepted();
    }

    LOG_CONN_DEBUG(ctx, "[Session] Transport ready ({}/{})",
                   listener.stream_settings.security,
                   listener.stream_settings.network);

    if (!proxy_) {
        stats.OnError();
        access_log.Fail(ErrorCode::INTERNAL);
        co_return;
    }
    try {
        auto relay_result = co_await proxy_->Process(
            std::move(stream),
            dispatcher,
            listener,
            io_context,
            ctx,
            timeouts,
            request_load.PressureIdleTimeout());
        access_log.Complete(relay_result);
    } catch (const std::exception& e) {
        LOG_CONN_WARN(ctx, "[Session] inbound process exception: {}", e.what());
        stats.OnError();
        access_log.Fail(ErrorCode::INTERNAL);
    } catch (...) {
        LOG_CONN_WARN(ctx, "[Session] inbound process exception: unknown");
        stats.OnError();
        access_log.Fail(ErrorCode::INTERNAL);
    }
}

}  // namespace acpp::proxyman::inbound
