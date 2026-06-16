#include "acppnode/app/proxyman/inbound/handler.hpp"

#include "acppnode/app/rate_limiter.hpp"
#include "acppnode/common/allocator.hpp"
#include "acppnode/common/ip_utils.hpp"
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
    target.inbound = source.inbound;
    target.inbound.user_id = 0;
    target.inbound.user_email.clear();
    target.sockopt = source.sockopt;
}

class LogicalTransportStreamSink final
    : public InboundTransportStreamHandler
    , public std::enable_shared_from_this<LogicalTransportStreamSink> {
public:
    LogicalTransportStreamSink(Handler& handler,
                               net::io_context& io_context,
                               routing::Dispatcher& dispatcher,
                               StatsShard& stats,
                               const TimeoutsConfig& timeouts,
                               const session::Context& base_ctx,
                               uint32_t pressure_idle_timeout)
        : handler_(handler)
        , io_context_(io_context)
        , dispatcher_(dispatcher)
        , stats_(stats)
        , timeouts_(timeouts)
        , pressure_idle_timeout_(pressure_idle_timeout) {
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
                co_await self->handler_.ProcessPreparedTransportStream(
                    self->io_context_,
                    self->dispatcher_,
                    self->stats_,
                    self->timeouts_,
                    std::move(stream),
                    ctx,
                    self->pressure_idle_timeout_);
            },
            net::detached);
    }

private:
    Handler& handler_;
    net::io_context& io_context_;
    routing::Dispatcher& dispatcher_;
    StatsShard& stats_;
    TimeoutsConfig timeouts_;
    uint32_t pressure_idle_timeout_ = 0;
    session::Context base_ctx_;
};

}  // namespace

Handler::Handler(inbound::ReceiverSettings receiver, std::unique_ptr<Inbound> proxy)
    : receiver_(std::move(receiver))
    , proxy_(std::move(proxy)) {}

void Handler::SetBanTrackingEnabled(bool enabled) noexcept {
    if (proxy_) {
        proxy_->SetBanTrackingEnabled(enabled);
    }
}

net::awaitable<void> Handler::ProcessPreparedTransportStream(
    net::io_context& io_context,
    routing::Dispatcher& dispatcher,
    StatsShard& stats,
    const TimeoutsConfig& timeouts,
    std::unique_ptr<AsyncStream> stream,
    session::Context& ctx,
    uint32_t pressure_idle_timeout) {
    const inbound::ReceiverSettings& listener = receiver_;
    ConnectionStatsScope connection_stats(stats);

    if (!stream) {
        stats.OnError();
        co_return;
    }

    if (listener.limiter &&
        listener.limiter->GetLimiter().IsBanned(ctx.inbound.tag, ctx.inbound.source_ip)) {
        LOG_ACCESS_FMT("{} from {}:{} rejected ip_banned [{}] (logical)",
            FormatTimestamp(ctx.accept_time_us),
            ctx.inbound.source_ip, ctx.inbound.source_port, ctx.inbound.tag);
        stats.OnError();
        co_return;
    }

    std::optional<ConnectionLimitScope> connection_limit;
    if (listener.limiter) {
        auto reject = listener.limiter->TryAcceptGlobal();
        if (reject != ConnectionLimiter::RejectReason::NONE) {
            LOG_ACCESS_FMT("{} from {}:{} rejected conn_limit [{}] reason={}",
                FormatTimestamp(ctx.accept_time_us),
                ctx.inbound.source_ip, ctx.inbound.source_port, ctx.inbound.tag,
                ConnectionLimiter::RejectReasonToString(reject));
            stats.OnError();
            co_return;
        }
        connection_limit.emplace(listener.limiter, ctx.inbound.source_ip);
        reject = listener.limiter->TryAcceptIP(ctx.inbound.tag, ctx.inbound.source_ip);
        if (reject != ConnectionLimiter::RejectReason::NONE) {
            LOG_ACCESS_FMT("{} from {}:{} rejected conn_limit [{}] reason={}",
                FormatTimestamp(ctx.accept_time_us),
                ctx.inbound.source_ip, ctx.inbound.source_port, ctx.inbound.tag,
                ConnectionLimiter::RejectReasonToString(reject));
            stats.OnError();
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
            pressure_idle_timeout);
        (void)relay_result;
    } catch (const std::exception& e) {
        LOG_CONN_FAIL_CTX(ctx, "[Session] logical inbound process exception: {}", e.what());
        stats.OnError();
    } catch (...) {
        LOG_CONN_FAIL_CTX(ctx, "[Session] logical inbound process exception: unknown");
        stats.OnError();
    }
}

net::awaitable<void> Handler::ProcessAcceptedTCP(
    net::io_context& io_context,
    routing::Dispatcher& dispatcher,
    StatsShard& stats,
    const TimeoutsConfig& timeouts,
    std::unique_ptr<AsyncStream> raw_conn,
    session::Context& ctx,
    uint32_t pressure_idle_timeout) {
    const inbound::ReceiverSettings& listener = receiver_;
    ConnectionStatsScope connection_stats(stats);

    if (listener.limiter &&
        listener.limiter->GetLimiter().IsBanned(ctx.inbound.tag, ctx.inbound.source_ip)) {
        LOG_ACCESS_FMT("{} from {}:{} rejected ip_banned [{}] (early)",
            FormatTimestamp(ctx.accept_time_us),
            ctx.inbound.source_ip, ctx.inbound.source_port, ctx.inbound.tag);
        stats.OnError();
        co_return;
    }

    std::optional<ConnectionLimitScope> connection_limit;
    if (listener.limiter) {
        auto reject = listener.limiter->TryAcceptGlobal();
        if (reject != ConnectionLimiter::RejectReason::NONE) {
            LOG_ACCESS_FMT("{} from {}:{} rejected conn_limit [{}] reason={}",
                FormatTimestamp(ctx.accept_time_us),
                ctx.inbound.source_ip, ctx.inbound.source_port, ctx.inbound.tag,
                ConnectionLimiter::RejectReasonToString(reject));
            stats.OnError();
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

    std::shared_ptr<InboundTransportStreamHandler> logical_stream_handler;
    if (listener.stream_settings.IsGrpc() ||
        listener.stream_settings.IsHttp() ||
        listener.stream_settings.IsXHttp()) {
        logical_stream_handler = std::make_shared<LogicalTransportStreamSink>(
            *this,
            io_context,
            dispatcher,
            stats,
            timeouts,
            ctx,
            pressure_idle_timeout);
    }

    std::string ws_real_ip;
    auto build_result = co_await BuildInboundTransport(
        io_context,
        std::move(raw_conn), listener.stream_settings,
        listener.stream_settings.NeedsHttpRealIpExtraction() ? &ws_real_ip : nullptr,
        ctx.conn_id,
        std::move(logical_stream_handler));

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
        IoErrorCode real_ip_ec;
        auto parsed_real_ip = net::ip::make_address(ws_real_ip, real_ip_ec);
        if (!real_ip_ec) {
            parsed_real_ip = iputil::NormalizeAddress(parsed_real_ip);
            ws_real_ip = parsed_real_ip.to_string();
        }
        LOG_CONN_DEBUG(ctx, "[Session] HTTP transport real IP from header: {} -> {}",
                       ctx.inbound.source_ip, ws_real_ip);
        ctx.inbound.source_addr = real_ip_ec ? net::ip::address{} : parsed_real_ip;
        ctx.inbound.source_ip = std::move(ws_real_ip);
    }

    if (connection_limit && listener.limiter) {
        connection_limit->UpdateIP(ctx.inbound.source_ip);
        auto reject = listener.limiter->TryAcceptIP(ctx.inbound.tag, ctx.inbound.source_ip);
        if (reject != ConnectionLimiter::RejectReason::NONE) {
            LOG_ACCESS_FMT("{} from {}:{} rejected conn_limit [{}] reason={}",
                FormatTimestamp(ctx.accept_time_us),
                ctx.inbound.source_ip, ctx.inbound.source_port, ctx.inbound.tag,
                ConnectionLimiter::RejectReasonToString(reject));
            stats.OnError();
            co_return;
        }
        connection_limit->MarkIPAccepted();
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
            io_context,
            ctx,
            timeouts,
            pressure_idle_timeout);
        (void)relay_result;
    } catch (const std::exception& e) {
        LOG_CONN_FAIL_CTX(ctx, "[Session] inbound process exception: {}", e.what());
        stats.OnError();
    } catch (...) {
        LOG_CONN_FAIL_CTX(ctx, "[Session] inbound process exception: unknown");
        stats.OnError();
    }
}

}  // namespace acpp::proxyman::inbound
