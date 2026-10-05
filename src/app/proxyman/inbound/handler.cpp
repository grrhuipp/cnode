#include "acppnode/app/proxyman/inbound/handler.hpp"
#include "acppnode/common/ip_address.hpp"


#include "acppnode/app/rate_limiter.hpp"
#include "acppnode/common/allocator.hpp"
#include "acppnode/common/ip_utils.hpp"
#include "acppnode/common/session.hpp"
#include "acppnode/infra/config_types.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/proxy/inbound.hpp"
#include "acppnode/transport/internet/transport_stack.hpp"
#include "acppnode/transport/link_error.hpp"

#include <asio/co_spawn.hpp>
#include "../../../common/awaitable_task_group.hpp"
#include <asio/this_coro.hpp>
#include <exception>
#include <new>
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
    const auto literal = iputil::ParseLiteral(real_ip);
    if (!literal) return;
    const auto address = iputil::NormalizeAddress(*literal);
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

void ApplyProxyProtocolResult(
    session::Context& ctx,
    const ProxyProtocolResult& result) {
    if (!result.success()) {
        return;
    }

    if (result.src_addr) {
        const auto source = iputil::NormalizeAddress(*result.src_addr);
        ctx.inbound.source_addr = source;
        ctx.inbound.source_ip = source.to_string();
    } else if (!result.src_ip.empty()) {
        ctx.inbound.source_addr = net::ip::address{};
        ctx.inbound.source_ip = result.src_ip;
    } else {
        return;
    }

    ctx.inbound.source_port = result.src_port;
    ctx.inbound.client_ip_source = "proxy_protocol";
    ctx.inbound.client_ip_trusted = true;
    LOG_CONN_DEBUG(
        ctx,
        "[{}] PROXY protocol: proxy={} real_ip={}:{}",
        ctx.inbound.tag,
        ctx.inbound.peer_ip,
        ctx.inbound.source_ip,
        ctx.inbound.source_port);
}

class ConnectionLimitScope {
public:
    explicit ConnectionLimitScope(ConnectionLimiterPtr limiter) : limiter_(limiter) {}
    net::awaitable<ConnectionLimiter::RejectReason> AcquireGlobal() {
        auto admission = co_await limiter_->AcquireGlobal();
        permit_ = std::move(admission.permit);
        co_return admission.reason;
    }
    net::awaitable<ConnectionLimiter::RejectReason> AcquireIP(
        std::string tag, std::string ip, bool check_auth_ban) {
        co_return co_await limiter_->AcquireIP(*permit_, std::move(tag), std::move(ip), check_auth_ban);
    }
    net::awaitable<void> Release() {
        if (permit_) {
            co_await limiter_->Release(std::move(*permit_));
            permit_.reset();
        }
    }
private:
    ConnectionLimiterPtr limiter_;
    std::optional<ConnectionLimiter::Permit> permit_;
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
                              session::Context& target, uint64_t stream_id = 0) {
    target.conn_id = stream_id ? session::ChildID(source.conn_id, stream_id) : source.conn_id;
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

}  // namespace

class Handler::LogicalTransportStreamSink final
    : public InboundTransportStreamHandler
    , public std::enable_shared_from_this<LogicalTransportStreamSink> {
public:
    LogicalTransportStreamSink(std::shared_ptr<Handler> handler,
                               AwaitableTaskGroup& tasks,
                               net::any_io_executor executor,
                               routing::Dispatcher& dispatcher,
                               StatsShard& stats,
                               uint32_t pressure_idle_timeout,
                               const TimeoutsConfig& timeouts,
                               const session::Context& base_ctx,
                               std::shared_ptr<InboundTransportMetadata> metadata,
                               int64_t transport_started_at_us)
        : handler_(std::move(handler))
        , tasks_(tasks)
        , executor_(executor)
        , dispatcher_(dispatcher)
        , stats_(stats)
        , pressure_idle_timeout_(pressure_idle_timeout)
        , timeouts_(timeouts)
        , base_ctx_(executor)
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
        if (active_streams_ >= 128) {
            stream->CloseAbortive();
            stats_.OnError();
            return;
        }
        auto self = shared_from_this();
        ++active_streams_;
        auto process = [](std::shared_ptr<LogicalTransportStreamSink> self,
                          std::unique_ptr<AsyncStream> stream) -> net::awaitable<void> {
                struct ActiveStream {
                    size_t& count;
                    ~ActiveStream() { --count; }
                } active{self->active_streams_};
                session::Context ctx(self->executor_);
                CopyTransportBaseContext(self->base_ctx_, ctx, ++self->next_stream_id_);
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
                    self->executor_,
                    self->dispatcher_,
                    self->stats_,
                    self->pressure_idle_timeout_,
                    self->timeouts_,
                    std::move(stream),
                    ctx);
            };
        try { tasks_.Spawn(process(std::move(self), std::move(stream))); }
        catch (...) { --active_streams_; throw; }
    }

private:
    std::shared_ptr<Handler> handler_;
    AwaitableTaskGroup& tasks_;
    size_t active_streams_ = 0;
    uint64_t next_stream_id_ = 0;
    net::any_io_executor executor_;
    routing::Dispatcher& dispatcher_;
    StatsShard& stats_;
    uint32_t pressure_idle_timeout_;
    TimeoutsConfig timeouts_;
    session::Context base_ctx_;
    std::shared_ptr<InboundTransportMetadata> metadata_;
    int64_t transport_started_at_us_ = 0;
};

Handler::Handler(inbound::ReceiverSettings receiver, std::unique_ptr<Inbound> proxy)
    : receiver_(std::move(receiver))
    , proxy_(std::move(proxy)) {}

net::awaitable<void> Handler::ProcessPreparedTransportStream(
    net::any_io_executor executor,
    routing::Dispatcher& dispatcher,
    StatsShard& stats,
    uint32_t pressure_idle_timeout,
    const TimeoutsConfig& timeouts,
    std::unique_ptr<AsyncStream> stream,
    session::Context& ctx) {
    ConnectionLimitScope connection_limit(receiver_.limiter);
    auto process = [&]() -> net::awaitable<void> {

    const inbound::ReceiverSettings& listener = receiver_;
    ConnectionStatsScope connection_stats(stats);

    ctx.inbound.protocol = listener.protocol;
    PrepareInboundLogMetadata(ctx, listener);

    if (!stream) {
        stats.OnError();
        co_return;
    }

    if (listener.limiter && ctx.inbound.HasProxyProtocolClientIP() &&
        (co_await listener.limiter->IsBanned(std::string(ctx.inbound.tag), std::string(ctx.inbound.source_ip)))) {
        LOG_CONN_DEBUG(ctx, "rejected ip_banned (logical) src={}:{}",
                       ctx.inbound.source_ip, ctx.inbound.source_port);
        stats.OnError();
        co_return;
    }

    if (listener.limiter) {
        auto reject = (co_await connection_limit.AcquireGlobal());
        if (reject != ConnectionLimiter::RejectReason::NONE) {
            LOG_CONN_DEBUG(ctx, "rejected conn_limit src={}:{} reason={}",
                           ctx.inbound.source_ip, ctx.inbound.source_port,
                           ConnectionLimiter::RejectReasonToString(reject));
            stats.OnError();
            co_return;
        }
        reject = (co_await connection_limit.AcquireIP(
            std::string(ctx.inbound.tag), std::string(ctx.inbound.source_ip),
            ctx.inbound.HasProxyProtocolClientIP()));
        if (reject != ConnectionLimiter::RejectReason::NONE) {
            LOG_CONN_DEBUG(ctx, "rejected conn_limit src={}:{} reason={}",
                           ctx.inbound.source_ip, ctx.inbound.source_port,
                           ConnectionLimiter::RejectReasonToString(reject));
            stats.OnError();
            co_return;
        }
    }

    stream->SetStreamLabel("in");
    stream->SetIdleTimeout(timeouts.HandshakeTimeout());
    (void)stream->StartPhaseDeadline(timeouts.HandshakeTimeout());

    LOG_CONN_DEBUG(ctx, "[Session] Logical transport stream ready ({}/{})",
                   listener.stream_settings.security,
                   listener.stream_settings.network);

    if (!proxy_) {
        stats.OnError();
        co_return;
    }
    try {
        auto relay_result = co_await proxy_->Process(
            std::move(stream),
            dispatcher,
            listener,
            executor,
            ctx,
            stats,
            timeouts,
            pressure_idle_timeout);
    } catch (const transport::LinkError&) {
        stats.OnError();
    } catch (const std::bad_alloc&) {
        stats.OnError();
    } catch (const IoSystemError&) {
        stats.OnError();
    } catch (const std::exception& e) {
        LOG_CONN_WARN(ctx, "[Session] logical inbound process exception: {}", e.what());
        stats.OnError();
    } catch (...) {
        LOG_CONN_WARN(ctx, "[Session] logical inbound process exception: unknown");
        stats.OnError();
    }

    };
    std::exception_ptr failure;
    try { co_await process(); }
    catch (...) { failure = std::current_exception(); }
    const bool throw_on_cancel = co_await net::this_coro::throw_if_cancelled();
    co_await net::this_coro::throw_if_cancelled(false);
    co_await connection_limit.Release();
    co_await net::this_coro::throw_if_cancelled(throw_on_cancel);
    if (failure) std::rethrow_exception(failure);
}

net::awaitable<void> Handler::ProcessAcceptedTCP(
    net::any_io_executor executor,
    routing::Dispatcher& dispatcher,
    StatsShard& stats,
    uint32_t pressure_idle_timeout,
    const TimeoutsConfig& timeouts,
    std::unique_ptr<AsyncStream> raw_conn,
    session::Context& ctx) {
    ConnectionLimitScope connection_limit(receiver_.limiter);
    auto process = [&]() -> net::awaitable<void> {

    const inbound::ReceiverSettings& listener = receiver_;
    ConnectionStatsScope connection_stats(stats);

    ctx.inbound.protocol = listener.protocol;
    PrepareInboundLogMetadata(ctx, listener);

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
                        2048);
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
            proxy_read.result.status != ProxyProtocolParseStatus::Success) {
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

    if (listener.limiter && ctx.inbound.HasProxyProtocolClientIP() &&
        (co_await listener.limiter->IsBanned(std::string(ctx.inbound.tag), std::string(ctx.inbound.source_ip)))) {
        LOG_CONN_DEBUG(ctx, "rejected ip_banned (early) src={}:{}",
                       ctx.inbound.source_ip, ctx.inbound.source_port);
        stats.OnError();
        co_return;
    }

    if (listener.limiter) {
        auto reject = (co_await connection_limit.AcquireGlobal());
        if (reject != ConnectionLimiter::RejectReason::NONE) {
            LOG_CONN_DEBUG(ctx, "rejected conn_limit src={}:{} reason={}",
                           ctx.inbound.source_ip, ctx.inbound.source_port,
                           ConnectionLimiter::RejectReasonToString(reject));
            stats.OnError();
            co_return;
        }
    }

    raw_conn->SetStreamLabel("in");
    raw_conn->SetIdleTimeout(timeouts.HandshakeTimeout());
    (void)raw_conn->StartPhaseDeadline(timeouts.HandshakeTimeout());

    LOG_CONN_DEBUG(ctx, "[Session] Building transport ({}/{})",
                   listener.stream_settings.security,
                   listener.stream_settings.network);

    const int64_t transport_started_at_us = NowMicros();
    auto transport_metadata = memory::AllocateShared<InboundTransportMetadata>();
    transport_metadata->real_ip_header =
        std::string(RealIpHeader(listener.stream_settings));
    std::string ws_real_ip;
    TransportBuildResult build_result = tl::unexpected(ErrorCode::INTERNAL);
    auto build_transport = [&](AwaitableTaskGroup& tasks,
        std::shared_ptr<InboundTransportStreamHandler> logical_stream_handler) -> net::awaitable<void> {
        build_result = co_await BuildInboundTransport(executor,
            std::move(raw_conn), listener.stream_settings,
            listener.stream_settings.NeedsHttpRealIpExtraction() ? &ws_real_ip : nullptr,
            ctx.conn_id, std::move(logical_stream_handler), transport_metadata.get(),
            listener.transport_scope_id);
        tasks.Cancel();
    };
    co_await RunAwaitableTaskGroup(executor, [&](AwaitableTaskGroup& tasks) {
        std::shared_ptr<InboundTransportStreamHandler> logical_stream_handler;
        if (listener.stream_settings.IsGrpc() || listener.stream_settings.IsHttp() ||
            listener.stream_settings.IsXHttp()) {
            logical_stream_handler = memory::AllocateShared<LogicalTransportStreamSink>(
                shared_from_this(), tasks, executor, dispatcher, stats, pressure_idle_timeout,
                timeouts, ctx, transport_metadata, transport_started_at_us);
        }
        tasks.Spawn(build_transport(tasks, std::move(logical_stream_handler)));
    });
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
        co_return;
    }
    auto stream = std::move(*build_result);
    if (!stream) {
        LOG_CONN_DEBUG(ctx, "[Session] Transport consumed connection ({}/{})",
                       listener.stream_settings.security,
                       listener.stream_settings.network);
        co_return;
    }

    if (!ws_real_ip.empty()) {
        LOG_CONN_DEBUG(ctx, "[Session] HTTP transport real IP from header: {} -> {}",
                       ctx.inbound.source_ip, ws_real_ip);
        ApplyHttpRealIp(
            ctx, ws_real_ip, RealIpHeader(listener.stream_settings));
    }

    if (listener.limiter) {
        auto reject = (co_await connection_limit.AcquireIP(
            std::string(ctx.inbound.tag), std::string(ctx.inbound.source_ip),
            ctx.inbound.HasProxyProtocolClientIP()));
        if (reject != ConnectionLimiter::RejectReason::NONE) {
            LOG_CONN_DEBUG(ctx, "rejected conn_limit src={}:{} reason={}",
                           ctx.inbound.source_ip, ctx.inbound.source_port,
                           ConnectionLimiter::RejectReasonToString(reject));
            stats.OnError();
            co_return;
        }
    }

    LOG_CONN_DEBUG(ctx, "[Session] Transport ready ({}/{})",
                   listener.stream_settings.security,
                   listener.stream_settings.network);

    if (!proxy_) {
        stats.OnError();
        co_return;
    }
    try {
        auto relay_result = co_await proxy_->Process(
            std::move(stream),
            dispatcher,
            listener,
            executor,
            ctx,
            stats,
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

    };
    std::exception_ptr failure;
    try { co_await process(); }
    catch (...) { failure = std::current_exception(); }
    const bool throw_on_cancel = co_await net::this_coro::throw_if_cancelled();
    co_await net::this_coro::throw_if_cancelled(false);
    co_await connection_limit.Release();
    co_await net::this_coro::throw_if_cancelled(throw_on_cancel);
    if (failure) std::rethrow_exception(failure);
}

}  // namespace acpp::proxyman::inbound
