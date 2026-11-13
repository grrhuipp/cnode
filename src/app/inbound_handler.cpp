#include "app/inbound_handler.hpp"
#include "app/rate_limiter.hpp"
#include "app/request_load.hpp"
#include "transport/quic_listener.hpp"
#include "app/stats.hpp"
#include "common/allocator.hpp"
#include "common/ip_address.hpp"
#include "common/session.hpp"
#include "infra/config_types.hpp"
#include "infra/log.hpp"
#include "proxy/inbound.hpp"
#include "proxy/inbound_admission.hpp"
#include "transport/proxy_protocol.hpp"
#include "transport/transport_stack.hpp"
#include <exception>
#include <map>
#include <new>
#include <stdexcept>
#include <string>
namespace app {

namespace {

void ApplyHttpRealIp(
    common::Context& ctx,
    std::string_view real_ip) {
    if (real_ip.empty()) return;
    const auto literal = common::ParseLiteral(real_ip);
    if (!literal) return;
    const auto address = common::NormalizeAddress(*literal);
    const auto normalized_ip = common::AddressText(address);
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
    ctx.inbound.client_ip_source = common::Inbound::ClientIpSource::HttpHeader;
}

void ApplyProxyProtocolResult(
    common::Context& ctx,
    const transport::ProxyProtocolResult& result) {
    if (!result.success() || !result.src_addr) {
        return;
    }

    const auto normalized_addr = common::NormalizeAddress(*result.src_addr);
    const auto normalized_ip = common::AddressText(normalized_addr);
    LOG_CONN_DEBUG(
        ctx,
        "PROXY protocol applied proxy={} real_ip={}:{}",
        ctx.inbound.source_ip,
        normalized_ip.View(),
        result.src_port);
    ctx.inbound.source_addr = normalized_addr;
    ctx.inbound.source_ip = normalized_ip.View();
    ctx.inbound.source_port = result.src_port;
    ctx.inbound.client_ip_source = common::Inbound::ClientIpSource::ProxyProtocol;
}

// 物理连接与逻辑子流共用的协议处理收尾：Process 自身已分类上报结果，
// 这里只把逃逸的异常收敛为一次错误统计，非预期异常额外记录。
// 只能在 catch 块内调用。
void CountEscapedInboundFailure(const common::Context& ctx, app::StatsShard& stats) {
    try {
        throw;
    } catch (const transport::LinkError&) {
    } catch (const std::bad_alloc&) {
    } catch (const IoSystemError&) {
    } catch (const std::exception& e) {
        LOG_CONN_WARN(ctx, "inbound processing failed > {}", e.what());
    } catch (...) {
        LOG_CONN_WARN(ctx, "inbound processing failed > unknown error");
    }
    stats.OnError();
}


}  // namespace

class InboundHandler::LogicalTransportStreamSink final
    : public transport::InboundTransportStreamHandler {
public:
    // HTTP/2-family transports authenticate per stream in the protocol, so
    // their children start anonymous; a transport that authenticated the
    // session (Hysteria) passes its bound identity to every child.
    LogicalTransportStreamSink(std::shared_ptr<InboundHandler> handler,
                               net::io_context& io_context,
                               routing::Dispatcher& dispatcher,
                               app::StatsShard& stats,
                               app::RequestLoadState& request_load,
                               const infra::TimeoutsConfig& timeouts,
                               const common::Context& base_ctx,
                               bool authenticated,
                               std::shared_ptr<app::ConnectionLimiter::Family> family)
        : handler_(std::move(handler))
        , io_context_(io_context)
        , dispatcher_(dispatcher)
        , stats_(stats)
        , request_load_(request_load)
        , timeouts_(timeouts) {
        // TCP 与 Hysteria 的 base_ctx 已携带本监听器的 accounting_key；
        // 子流经 InitSubstreamFrom 继承 connection_family 作为逻辑准入的物理族。
        base_ctx_.InitSubstreamFrom(base_ctx);
        base_ctx_.conn_id = base_ctx.conn_id;
        base_ctx_.inbound.connection_family = std::move(family);
        if (!authenticated) {
            base_ctx_.inbound.user_id = 0;
            base_ctx_.inbound.user_email.clear();
        }
    }
    void OnInboundTransportReady(transport::AsyncStream& stream) override {
        if (stream.ConsumePhaseDeadline()) {
            throw transport::LinkError(common::ErrorCode::TIMEOUT);
        }
        stream.ClearPhaseDeadline();
        stream.SetIdleTimeout(timeouts_.IdleTimeout());
    }

    void OnInboundTransportRequest(transport::AsyncStream& stream) override {
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
        std::unique_ptr<transport::AsyncStream> stream,
        transport::InboundTransportMetadata metadata) override {
        if (!stream) {
            co_return;
        }
        common::Context ctx;
        ctx.InitSubstreamFrom(base_ctx_);
        ApplyHttpRealIp(ctx, metadata.real_ip);
        // 传输层已识别的原生 UDP 会话（Hysteria）在入站处理前即确定网络与首个目标。
        if (metadata.udp_session_target) {
            ctx.content.network = common::Network::UDP;
            ctx.outbound.target = std::move(*metadata.udp_session_target);
        }

        InboundHandler& handler = *handler_;
        const app::ReceiverSettings& listener = handler.receiver_;
        proxy::InboundSubstreamAdmission admission(stats_);
        if (!co_await admission.Admit(handler.environment_, ctx)) co_return;

        (void)stream->StartPhaseDeadline(timeouts_.HandshakeTimeout());

        LOG_CONN_DEBUG(ctx, "logical transport stream ready security={} network={}",
                       transport::SecurityModeName(listener.stream_settings.security_mode),
                       listener.stream_settings.NetworkName());

        proxy::Inbound& proxy = *handler.proxy_;
        try {
            (void)co_await proxy.Process(
                std::move(stream), dispatcher_, listener, io_context_, ctx, timeouts_,
                request_load_.PressureIdleTimeout());
        } catch (...) {
            CountEscapedInboundFailure(ctx, stats_);
        }
    }

private:
    std::shared_ptr<InboundHandler> handler_;
    net::io_context& io_context_;
    routing::Dispatcher& dispatcher_;
    app::StatsShard& stats_;
    app::RequestLoadState& request_load_;
    infra::TimeoutsConfig timeouts_;
    common::Context base_ctx_;
};

InboundHandler::InboundHandler(app::ReceiverSettings receiver, std::unique_ptr<proxy::Inbound> proxy,
                               const AdmissionEnvironment& environment)
    : receiver_(std::move(receiver))
    , security_(receiver_.stream_settings, transport::StreamEndpointRole::Inbound)
    , proxy_(std::move(proxy))
    , environment_(environment) {
    if (!proxy_) throw std::logic_error("inbound handler has no protocol");
}
std::shared_ptr<transport::InboundTransportStreamHandler> InboundHandler::NewAuthenticatedStreamSink(
    net::io_context& io_context,
    routing::Dispatcher& dispatcher,
    app::StatsShard& stats,
    app::RequestLoadState& request_load,
    const infra::TimeoutsConfig& timeouts,
    const common::Context& session_ctx,
    std::shared_ptr<app::ConnectionLimiter::Family> family) {
    return std::make_shared<LogicalTransportStreamSink>(
        shared_from_this(), io_context, dispatcher, stats, request_load, timeouts,
        session_ctx, true, std::move(family));
}

net::awaitable<void> InboundHandler::ProcessAcceptedTCP(
    net::io_context& io_context,
    routing::Dispatcher& dispatcher,
    app::StatsShard& stats,
    app::RequestLoadState& request_load,
    const infra::TimeoutsConfig& timeouts,
    std::unique_ptr<transport::AsyncStream> raw_conn,
    common::Context& ctx,
    app::DNS* dns_service) {
    const app::ReceiverSettings& listener = receiver_;
    app::ConnectionStatsScope connection_stats(stats);

    ctx.inbound.accounting_key.assign(listener.accounting_key);

    if (!raw_conn) {
        stats.OnError();
        co_return;
    }

    if (listener.proxy_protocol != transport::ProxyProtocolMode::Off) {
        auto proxy_read = co_await transport::ReadInboundProxyProtocol(
            *raw_conn,
            timeouts.HandshakeTimeout());
        if (!proxy_read.ok()) {
            switch (proxy_read.status) {
                case transport::ProxyProtocolReadStatus::TimedOut:
                    LOG_CONN_WARN(
                        ctx,
                        "failed to read PROXY protocol client={} > i/o timeout",
                        ctx.inbound.source_ip);
                    break;
                case transport::ProxyProtocolReadStatus::Truncated:
                    if (proxy_read.result.status == transport::ProxyProtocolParseStatus::NotProxy) {
                        LOG_CONN_DEBUG(ctx, "connection ended before PROXY protocol header from {}:{}",
                                       ctx.inbound.source_ip, ctx.inbound.source_port);
                    } else {
                        LOG_CONN_WARN(ctx, "failed to read PROXY protocol from {}:{} > truncated header",
                                      ctx.inbound.source_ip, ctx.inbound.source_port);
                    }
                    break;
                case transport::ProxyProtocolReadStatus::TooLarge:
                    LOG_CONN_WARN(
                        ctx,
                        "failed to read PROXY protocol > header too large limit={}B",
                        transport::kProxyHeaderMaxBytes);
                    break;
                case transport::ProxyProtocolReadStatus::Invalid:
                    LOG_CONN_WARN(ctx, "failed to read PROXY protocol > invalid header");
                    break;
                case transport::ProxyProtocolReadStatus::Ok:
                    break;
            }
            stats.OnError();
            raw_conn->CloseAbortive();
            co_return;
        }

        if (listener.proxy_protocol == transport::ProxyProtocolMode::On &&
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

    app::ConnectionLimiter::Admission physical_admission;
    if (auto pending = proxy::ReserveInboundConnection(environment_, app::ConnectionLimiter::ReservationScope::Physical, ctx)) {
        physical_admission = co_await std::move(*pending);
    }
    auto reject = physical_admission.reason;
    if (reject != app::ConnectionLimiter::RejectReason::NONE) {
        proxy::RejectInboundAdmission(ctx, stats, reject);
        co_return;
    }
    auto connection_limit = std::move(physical_admission.reservation);
    ctx.inbound.connection_family = connection_limit.FamilyLease();

    raw_conn->SetIdleTimeout(timeouts.HandshakeTimeout());
    (void)raw_conn->StartPhaseDeadline(timeouts.HandshakeTimeout());

    LOG_CONN_DEBUG(ctx, "building transport security={} network={}",
                   transport::SecurityModeName(listener.stream_settings.security_mode),
                   listener.stream_settings.NetworkName());

    transport::InboundTransportMetadata local_metadata;
    std::shared_ptr<LogicalTransportStreamSink> logical_stream_handler;
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
            false,
            connection_limit.FamilyLease());
    }
    // The physical reservation above stays held while a REALITY fallback runs
    // inside the transport build.
    const transport::InboundFallbackContext fallback{
        .ctx = ctx, .stats = stats, .timeouts = timeouts, .dns_service = dns_service};
    auto build_result = co_await transport::BuildInboundTransport(
        environment_.coordinator,
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
                       transport::SecurityModeName(listener.stream_settings.security_mode),
                       listener.stream_settings.NetworkName());
        stats.OnError();
        co_return;
    }
    auto stream = std::move(*build_result);
    if (!stream) {
        LOG_CONN_DEBUG(ctx, "transport consumed connection security={} network={}",
                       transport::SecurityModeName(listener.stream_settings.security_mode),
                       listener.stream_settings.NetworkName());
        co_return;
    }

    ApplyHttpRealIp(ctx, local_metadata.real_ip);
    local_metadata = {};
    app::ConnectionLimiter::Admission ip_admission;
    if (auto pending = proxy::ReserveInboundConnection(environment_, app::ConnectionLimiter::ReservationScope::ClientIp, ctx)) {
        ip_admission = co_await std::move(*pending);
    }
    reject = ip_admission.reason;
    if (reject != app::ConnectionLimiter::RejectReason::NONE) {
        proxy::RejectInboundAdmission(ctx, stats, reject);
        co_return;
    }
    auto ip_limit = std::move(ip_admission.reservation);

    LOG_CONN_DEBUG(ctx, "transport ready security={} network={}",
                   transport::SecurityModeName(listener.stream_settings.security_mode),
                   listener.stream_settings.NetworkName());

    proxy::Inbound& proxy = *proxy_;
    try {
        (void)co_await proxy.Process(
            std::move(stream), dispatcher, listener, io_context, ctx, timeouts,
            request_load.PressureIdleTimeout());
    } catch (...) {
        CountEscapedInboundFailure(ctx, stats);
    }
}

// ============================================================================
// Inbound Factory Registration
// ============================================================================

namespace {

using RegistrationMap = std::map<std::string, ProxyRegistration, std::less<>>;

RegistrationMap& Registrations() noexcept {
    static RegistrationMap registrations;
    return registrations;
}

// 注册表在静态初始化后只读；所有按协议名的查询都经此唯一入口。
[[nodiscard]] const ProxyRegistration* FindRegistration(std::string_view protocol) noexcept {
    auto& registrations = Registrations();
    const auto it = registrations.find(protocol);
    return it == registrations.end() ? nullptr : &it->second;
}

}  // namespace

void RegisterProxy(
    std::string_view protocol,
    ProxyRegistration registration) {
    const bool has_user_builders = registration.build_users != nullptr;
    const bool has_tcp = registration.create_tcp_handler != nullptr;
    const bool has_packet_datagrams =
        registration.create_datagram_handler != nullptr;
    const bool transport_consistent =
        (registration.datagram_transport == DatagramTransport::Packet) ==
            has_packet_datagrams;
    const bool has_quic = registration.create_quic_listener != nullptr;
    if (protocol.empty() || !has_tcp ||
        !transport_consistent ||
        (registration.datagram_transport == DatagramTransport::Quic) != has_quic ||
        has_user_builders != registration.user_protocol.has_value()) {
        throw std::invalid_argument(
            "invalid inbound protocol registration for '" +
            std::string(protocol) + "'");
    }
    if (!Registrations().try_emplace(
            std::string(protocol), std::move(registration)).second) {
        throw std::logic_error(
            "duplicate inbound protocol registration for '" +
            std::string(protocol) + "'");
    }
}

bool HasProxy(std::string_view protocol) {
    return FindRegistration(protocol) != nullptr;
}

std::optional<UserProtocol> RegisteredUserProtocol(
    std::string_view protocol) {
    const auto* registration = FindRegistration(protocol);
    return registration ? registration->user_protocol : std::nullopt;
}

DatagramTransport RegisteredDatagramTransport(
    std::string_view protocol) {
    const auto* registration = FindRegistration(protocol);
    return registration ? registration->datagram_transport : DatagramTransport::None;
}

InboundProtocolTraits RegisteredProtocolTraits(std::string_view protocol) {
    const auto* registration = FindRegistration(protocol);
    return registration ? registration->traits : InboundProtocolTraits{};
}

std::unique_ptr<transport::QuicListener> NewQuicListener(
    std::string_view protocol, uint32_t worker_id, uint32_t worker_count,
    net::io_context& io, app::DatagramSessionEnvironment environment) {
    const auto* registration = FindRegistration(protocol);
    if (!registration || !registration->create_quic_listener) return nullptr;
    if (worker_count == 0 || worker_id >= worker_count)
        throw std::invalid_argument("invalid QUIC worker topology");
    return registration->create_quic_listener(worker_id, worker_count, io, std::move(environment));
}

std::optional<BuildRequest> PrepareBuildRequest(
    std::string_view protocol,
    std::string_view tag,
    const ::infra::InboundProtocolSettings& settings) {
    const auto* registration = FindRegistration(protocol);
    if (!registration) {
        return std::nullopt;
    }

    BuildRequest request{
        .tag = std::string(tag),
        .protocol = std::string(protocol),
        .settings = {},
    };
    if (registration->prepare_settings) {
        auto prepared = registration->prepare_settings(tag, settings);
        if (!prepared) {
            return std::nullopt;
        }
        request.settings = std::move(*prepared);
    }
    return request;
}

std::optional<UserSet> BuildUsers(
    const BuildRequest& req,
    std::span<const ::infra::InboundUserSpec> users) {
    const auto* registration = FindRegistration(req.protocol);
    if (!registration || !registration->build_users) {
        return std::nullopt;
    }
    auto result = registration->build_users(req, users);
    if (result && UserProtocolOf(*result) != *registration->user_protocol) {
        return std::nullopt;
    }
    return result;
}

// ============================================================================
// HandlerRegistry
// ============================================================================

InboundHandlerRegistry::InboundHandlerRegistry(const AdmissionEnvironment& environment)
    : environment_(environment) {}

InboundHandlerRegistry::~InboundHandlerRegistry() noexcept = default;

InboundHandlerRegistry::HandlerPtr InboundHandlerRegistry::GetHandler(std::string_view tag) noexcept {
    auto it = handlers_.find(tag);
    return it == handlers_.end() ? nullptr : it->second;
}

std::unique_ptr<::proxy::Inbound> InboundHandlerRegistry::NewHandler(
    const BuildRequest& req) {
    const auto* registration = FindRegistration(req.protocol);
    if (!registration) return nullptr;
    return registration->create_tcp_handler(environment_, req);
}

DatagramHandlerBuildResult InboundHandlerRegistry::NewDatagramHandler(
    const BuildRequest& req) {
    const auto* registration = FindRegistration(req.protocol);
    if (!registration) return {DatagramHandlerBuildStatus::Failed, nullptr};
    if (!registration->create_datagram_handler) {
        return {DatagramHandlerBuildStatus::Unsupported, nullptr};
    }
    auto handler = registration->create_datagram_handler(
        environment_, req);
    if (!handler) {
        return {DatagramHandlerBuildStatus::Failed, nullptr};
    }
    return {DatagramHandlerBuildStatus::Ready, std::move(handler)};
}


InboundHandlerRegistry::HandlerPtr InboundHandlerRegistry::ReplaceHandler(std::unique_ptr<InboundHandler> handler) {
    if (!handler) {
        return nullptr;
    }

    std::string tag(handler->Tag());
    auto shared_handler = std::shared_ptr<InboundHandler>(std::move(handler));
    return handlers_.insert_or_assign(
        std::move(tag), std::move(shared_handler)).first->second;
}

void InboundHandlerRegistry::RemoveHandler(std::string_view tag) {
    auto it = handlers_.find(tag);
    if (it == handlers_.end()) {
        return;
    }

    handlers_.erase(it);
    common::MaybeShrinkHashContainer(handlers_, 8);
}

}  // namespace app
