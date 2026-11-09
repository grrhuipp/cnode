#include "app/proxyman/inbound/handler.hpp"
#include "app/proxyman/inbound/handler_registry.hpp"
#include "app/proxyman/inbound/factory.hpp"
#include "common/ip_address.hpp"

#include "app/rate_limiter.hpp"
#include "app/stats.hpp"
#include "common/allocator.hpp"
#include "common/ip_utils.hpp"
#include "common/session.hpp"
#include "infra/config_types.hpp"
#include "infra/log.hpp"
#include "proxy/inbound.hpp"
#include "transport/internet/proxy_protocol.hpp"
#include "transport/internet/transport_stack.hpp"

#include <exception>
#include <new>

namespace proxyman::inbound {

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
    const auto normalized_ip = iputil::AddressText(address);
    LOG_CONN_DEBUG(
        ctx,
        "HTTP transport client address overridden by header: {} -> {}",
        ctx.inbound.source_ip,
        normalized_ip.View());
    ctx.inbound.source_addr = address;
    ctx.inbound.source_ip = normalized_ip.View();
    // Forwarded address headers do not reliably carry the original client
    // port. Zero is explicit unknown; retaining the CDN port is a false tuple.
    ctx.inbound.source_port = 0;
    ctx.inbound.client_ip_source = session::Inbound::ClientIpSource::HttpHeader;
}

void ApplyProxyProtocolResult(
    session::Context& ctx,
    const ProxyProtocolResult& result) {
    if (!result.success() || !result.src_addr) {
        return;
    }

    const auto normalized_addr = iputil::NormalizeAddress(*result.src_addr);
    const auto normalized_ip = iputil::AddressText(normalized_addr);
    LOG_CONN_DEBUG(
        ctx,
        "PROXY protocol applied proxy={} real_ip={}:{}",
        ctx.inbound.source_ip,
        normalized_ip.View(),
        result.src_port);
    ctx.inbound.source_addr = normalized_addr;
    ctx.inbound.source_ip = normalized_ip.View();
    ctx.inbound.source_port = result.src_port;
    ctx.inbound.client_ip_source = session::Inbound::ClientIpSource::ProxyProtocol;
}

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
        LOG_CONN_WARN(ctx, "inbound processing failed > {}", e.what());
        stats.OnError();
    } catch (...) {
        LOG_CONN_WARN(ctx, "inbound processing failed > unknown error");
        stats.OnError();
    }
}

void RejectConnection(
    const session::Context& ctx,
    StatsShard& stats,
    ConnectionLimiter::RejectReason reject,
    bool before_transport_handshake = false) {
    const char* reason = ConnectionLimiter::RejectReasonToString(reject);
    if (before_transport_handshake &&
        reject == ConnectionLimiter::RejectReason::IP_BANNED) {
        LOG_CONN_DEBUG(ctx, "connection rejected source={}:{} > IP banned before transport handshake",
                       ctx.inbound.source_ip, ctx.inbound.source_port);
    } else {
        LOG_CONN_DEBUG(ctx, "connection rejected from {}:{} > {}",
                       ctx.inbound.source_ip, ctx.inbound.source_port, reason);
    }
    LOG_ACCESS(FormatAccessLog(ctx, AccessStatus::Rejected, reason));
    stats.OnError();
}

}  // namespace

class Handler::LogicalTransportStreamSink final
    : public InboundTransportStreamHandler {
public:
    // HTTP/2-family transports authenticate per stream in the protocol, so
    // their children start anonymous; a transport that authenticated the
    // session (Hysteria) passes its bound identity to every child.
    LogicalTransportStreamSink(std::shared_ptr<Handler> handler,
                               net::io_context& io_context,
                               routing::Dispatcher& dispatcher,
                               StatsShard& stats,
                               app::RequestLoadState& request_load,
                               const TimeoutsConfig& timeouts,
                               const session::Context& base_ctx,
                               bool authenticated,
                               std::shared_ptr<ConnectionLimiter::Family> family)
        : handler_(std::move(handler))
        , io_context_(io_context)
        , dispatcher_(dispatcher)
        , stats_(stats)
        , request_load_(request_load)
        , timeouts_(timeouts)
        , family_(std::move(family)) {
        base_ctx_.InitSubstreamFrom(base_ctx);
        base_ctx_.conn_id = base_ctx.conn_id;
        base_ctx_.inbound.accounting_key.assign(handler_->receiver_.accounting_key);
        base_ctx_.inbound.connection_family = family_;
        if (!authenticated) {
            base_ctx_.inbound.user_id = 0;
            base_ctx_.inbound.user_email.clear();
        }
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

    std::chrono::seconds TransportHandshakeTimeout() const noexcept override {
        return timeouts_.HandshakeTimeout();
    }

    std::chrono::seconds TransportIdleTimeout() const noexcept override {
        return timeouts_.IdleTimeout();
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
    std::shared_ptr<ConnectionLimiter::Family> family_;
};

Handler::Handler(inbound::ReceiverSettings receiver, std::unique_ptr<Inbound> proxy,
                 ConnectionLimiter& limiter)
    : receiver_(std::move(receiver))
    , security_(receiver_.stream_settings, StreamEndpointRole::Inbound)
    , proxy_(std::move(proxy))
    , limiter_(limiter) {}

Inbound& Handler::Proxy() {
    if (!proxy_) throw std::logic_error("inbound handler has no protocol");
    return *proxy_;
}
std::shared_ptr<InboundTransportStreamHandler> Handler::NewAuthenticatedStreamSink(
    net::io_context& io_context,
    routing::Dispatcher& dispatcher,
    StatsShard& stats,
    app::RequestLoadState& request_load,
    const TimeoutsConfig& timeouts,
    const session::Context& session_ctx,
    std::shared_ptr<ConnectionLimiter::Family> family) {
    return memory::AllocateShared<LogicalTransportStreamSink>(
        shared_from_this(), io_context, dispatcher, stats, request_load, timeouts,
        session_ctx, true, std::move(family));
}

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

    auto admission = co_await limiter_.ReserveLogical(
        family, ctx.inbound.tag, ctx.inbound.source_ip,
        ctx.inbound.HasProxyProtocolClientIP());
    const auto reject = admission.reason;
    if (reject != ConnectionLimiter::RejectReason::NONE) {
        RejectConnection(ctx, stats, reject);
        co_return;
    }
    auto connection_limit = std::move(admission.reservation);

    (void)stream->StartPhaseDeadline(timeouts.HandshakeTimeout());

    LOG_CONN_DEBUG(ctx, "logical transport stream ready security={} network={}",
                   listener.stream_settings.security,
                   listener.stream_settings.network);

    co_await RunInboundProxy(
        Proxy(), std::move(stream), dispatcher, listener, io_context, ctx, timeouts,
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
                    if (proxy_read.result.status == ProxyProtocolParseStatus::NotProxy) {
                        LOG_CONN_DEBUG(ctx, "connection ended before PROXY protocol header from {}:{}",
                                       ctx.inbound.source_ip, ctx.inbound.source_port);
                    } else {
                        LOG_CONN_WARN(ctx, "failed to read PROXY protocol from {}:{} > truncated header",
                                      ctx.inbound.source_ip, ctx.inbound.source_port);
                    }
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

    auto physical_admission = co_await limiter_.ReservePhysical(
        ctx.inbound.tag, ctx.inbound.source_ip,
        ctx.inbound.HasProxyProtocolClientIP());
    auto reject = physical_admission.reason;
    if (reject != ConnectionLimiter::RejectReason::NONE) {
        RejectConnection(ctx, stats, reject, true);
        co_return;
    }
    auto connection_limit = std::move(physical_admission.reservation);
    ctx.inbound.connection_family = connection_limit.FamilyLease();

    raw_conn->SetIdleTimeout(timeouts.HandshakeTimeout());
    (void)raw_conn->StartPhaseDeadline(timeouts.HandshakeTimeout());

    LOG_CONN_DEBUG(ctx, "building transport security={} network={}",
                   listener.stream_settings.security,
                   listener.stream_settings.network);

    InboundTransportMetadata local_metadata;
    local_metadata.real_ip_header.assign(RealIpHeader(listener.stream_settings));
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
            false,
            connection_limit.FamilyLease());
    }
    // The physical reservation above stays held while a REALITY fallback runs
    // inside the transport build.
    const InboundFallbackContext fallback{
        .ctx = ctx, .stats = stats, .timeouts = timeouts, .dns_service = dns_service};
    auto build_result = co_await BuildInboundTransport(
        io_context,
        std::move(raw_conn),
        listener.stream_settings,
        security_.Context(),
        ctx.conn_id,
        std::move(logical_stream_handler),
        &local_metadata,
        &fallback);
    if (!build_result) {
        LOG_CONN_DEBUG(ctx, "transport handshake failed security={} network={}",
                       listener.stream_settings.security,
                       listener.stream_settings.network);
        stats.OnError();
        co_return;
    }
    auto stream = std::move(*build_result);
    if (!stream) {
        LOG_CONN_DEBUG(ctx, "transport consumed connection security={} network={}",
                       listener.stream_settings.security,
                       listener.stream_settings.network);
        co_return;
    }

    ApplyHttpRealIp(ctx, local_metadata.real_ip);
    local_metadata = {};
    auto ip_admission = co_await limiter_.ReserveIP(
        ctx.inbound.tag, ctx.inbound.source_ip,
        ctx.inbound.HasProxyProtocolClientIP());
    reject = ip_admission.reason;
    if (reject != ConnectionLimiter::RejectReason::NONE) {
        RejectConnection(ctx, stats, reject);
        co_return;
    }
    auto ip_limit = std::move(ip_admission.reservation);

    LOG_CONN_DEBUG(ctx, "transport ready security={} network={}",
                   listener.stream_settings.security,
                   listener.stream_settings.network);

    co_await RunInboundProxy(
        Proxy(), std::move(stream), dispatcher, listener, io_context, ctx, timeouts,
        request_load.PressureIdleTimeout(), stats);
}

// ============================================================================
// HandlerRegistry
// ============================================================================

HandlerRegistry::HandlerRegistry(StatsShard& stats)
    : stats_(stats) {}

HandlerRegistry::~HandlerRegistry() noexcept = default;

HandlerRegistry::HandlerPtr HandlerRegistry::GetHandler(std::string_view tag) noexcept {
    auto it = handlers_.find(tag);
    return it == handlers_.end() ? nullptr : it->second;
}

std::unique_ptr<::Inbound> HandlerRegistry::NewHandler(
    ::ConnectionLimiter* limiter,
    const BuildRequest& req) {
    auto* runtime = GetOrCreateRuntime(req.protocol);
    if (!runtime) {
        return nullptr;
    }
    return ::proxyman::inbound::NewHandler(
        req.protocol, *runtime, stats_, limiter, req);
}

DatagramHandlerBuildResult HandlerRegistry::NewDatagramHandler(
    ::ConnectionLimiter* limiter,
    const BuildRequest& req) {
    auto* runtime = GetOrCreateRuntime(req.protocol);
    if (!runtime) {
        return {DatagramHandlerBuildStatus::Failed, nullptr};
    }
    return ::proxyman::inbound::NewDatagramHandler(
        req.protocol, *runtime, stats_, limiter, req);
}

ProtocolRuntime* HandlerRegistry::GetOrCreateRuntime(
    std::string_view protocol) {
    if (auto it = runtimes_.find(protocol); it != runtimes_.end()) {
        return it->second.get();
    }
    auto runtime = NewProtocolRuntime(protocol);
    if (!runtime) return nullptr;
    auto result = runtimes_.emplace(
        memory::ThreadLocalString(protocol), std::move(runtime));
    return result.first->second.get();
}

HandlerRegistry::HandlerPtr HandlerRegistry::ReplaceHandler(std::unique_ptr<Handler> handler) {
    if (!handler) {
        return nullptr;
    }

    memory::ThreadLocalString tag(handler->Tag());
    auto shared_handler = std::shared_ptr<Handler>(
        handler.release(), std::default_delete<Handler>{},
        memory::ThreadLocalAllocator<Handler>{});
    auto it = handlers_.find(tag);
    if (it == handlers_.end()) {
        auto [inserted_it, inserted] = handlers_.try_emplace(
            std::move(tag), std::move(shared_handler));
        return inserted ? inserted_it->second : nullptr;
    }

    it->second = std::move(shared_handler);
    return it->second;
}

void HandlerRegistry::RemoveHandler(std::string_view tag) {
    auto it = handlers_.find(tag);
    if (it == handlers_.end()) {
        return;
    }

    handlers_.erase(it);
}

std::vector<::OnlineDevice>
HandlerRegistry::GetOnlineDevices(std::string_view protocol, std::string_view tag) const {
    if (auto it = runtimes_.find(protocol); it != runtimes_.end()) {
        if (auto* tracker = it->second->OnlineTracker()) {
            return tracker->GetOnlineDevices(tag);
        }
    }
    return {};
}

}  // namespace proxyman::inbound
