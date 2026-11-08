#include "transport/internet/transport_stack.hpp"

#include "http1_handshake.hpp"
#include "http2_session.hpp"
#include "reality_tls.hpp"
#include "reality_client_hello.hpp"
#include "xhttp_session.hpp"
#include "app/relay.hpp"
#include "common/allocator.hpp"
#include "common/session.hpp"
#include "common/unsafe.hpp"
#include "infra/log.hpp"
#include "infra/runtime_config_types.hpp"
#include "transport/internet/http_headers.hpp"
#include "transport/internet/outbound_target_builder.hpp"
#include "transport/internet/tcp_stream.hpp"
#include "transport/internet/tls_stream.hpp"
#include "transport/internet/transport_dialer.hpp"
#include "transport/internet/ws_stream.hpp"

#include <algorithm>
#include <array>
#include <memory>
#include <span>
#include <string_view>


net::awaitable<ProxyProtocolReadResult> ReadInboundProxyProtocol(
    AsyncStream& raw,
    std::chrono::seconds timeout) {
    auto* tcp = dynamic_cast<TcpStream*>(&raw);
    if (!tcp) {
        ProxyProtocolReadResult result;
        result.status = ProxyProtocolReadStatus::Invalid;
        result.result.status = ProxyProtocolParseStatus::Invalid;
        co_return result;
    }
    co_return co_await tcp->ReadProxyProtocolHeader(timeout);
}

namespace {

using transport::internet::EqualsAsciiCI;
using transport::internet::TrimAscii;


[[nodiscard]] bool ReceivesSupportedReality(const StreamSettings& s) {
    return !s.IsReality() ||
           s.network_mode == NetworkMode::Tcp ||
           s.IsGrpc() ||
           s.IsXHttp();
}

std::unique_ptr<TcpStream> TakeOwnedTcpStream(std::unique_ptr<AsyncStream>& stream) {
    auto* tcp_raw = stream ? dynamic_cast<TcpStream*>(stream.get()) : nullptr;
    if (!tcp_raw) {
        return nullptr;
    }
    (void)stream.release();
    return std::unique_ptr<TcpStream>(tcp_raw);
}

// A configured Host wins over the dial-derived authority.
[[nodiscard]] std::string_view ResolveHttpAuthority(std::string_view fallback,
                                                    const HttpConfig& http) {
    if (const std::string_view configured = TrimAscii(transport::internet::ExpectedHttpHost(http));
        !configured.empty()) {
        return configured;
    }
    return fallback.empty() ? std::string_view("www.example.com") : fallback;
}

[[nodiscard]] bool OffersHttp2(const StreamSettings& s) {
    return !(s.tls.alpn.size() == 1 && EqualsAsciiCI(s.tls.alpn.front(), "http/1.1"));
}

[[nodiscard]] bool ShouldUseHttp2ForXHttp(const StreamSettings& s) {
    if (s.IsReality()) {
        return std::ranges::find(s.tls.alpn, "h2") != s.tls.alpn.end();
    }
    return s.IsTlsLike() && OffersHttp2(s);
}

[[nodiscard]] bool ShouldUseHttp2ForHttp(const StreamSettings& s) {
    return s.http.force_http2 || (s.IsTlsLike() && OffersHttp2(s));
}

// Xray keeps REALITY dest fallback in the transport layer. It dials dest through
// the shared outbound target builder/dialer and forwards with the shared relay
// (stats, timeouts, half-close, cancellation). The unauthenticated session never
// enters dispatch, routing or user accounting; the caller's physical admission
// reservation outlives BuildInboundTransport and so covers this whole relay.
net::awaitable<void> RunRealityFallbackProxy(
    net::io_context& io_context,
    const InboundFallbackContext& fallback,
    std::unique_ptr<TcpStream> client_tcp,
    const RealityConfig& reality,
    memory::ByteVector initial_bytes) {
    session::Context& ctx = fallback.ctx;
    const TimeoutsConfig& timeouts = fallback.timeouts;

    // A plain TCP dest; no send-through binding, as in Xray's dest dial.
    static const StreamSettings kRawTcp{};
    std::unique_ptr<AsyncStream> dest_stream;
    auto dest_target = co_await BuildOutboundTransportTarget(OutboundTargetOptions{
        .dns_service = fallback.dns_service,
        .address = reality.dest_host,
        .port = reality.dest_port,
        .stream_settings = &kRawTcp,
        .timeout = timeouts.DialTimeout(),
    });
    if (dest_target) {
        auto dial = co_await DialOutboundTransport(io_context, ctx, *dest_target);
        if (dial.Ok()) {
            dest_stream = std::move(dial.stream);
        } else {
            LOG_CONN_DEBUG(ctx, "REALITY fallback dial {}:{} failed > {}",
                           reality.dest_host, reality.dest_port, dial.error_msg);
        }
    } else {
        LOG_CONN_DEBUG(ctx, "REALITY fallback target {}:{} failed > {}",
                       reality.dest_host, reality.dest_port,
                       ErrorCodeToString(dest_target.error()));
    }

    if (!dest_stream || !client_tcp->IsOpen()) {
        if (dest_stream) dest_stream->CloseAbortive();
        client_tcp->CloseAbortive();
        co_return;
    }

    // The PROXY header and the sniffed ClientHello leave as the relay's first
    // upload write, so dest receives them in one gathered write as before.
    buf::MultiBuffer first;
    bool first_ok = true;
    if (reality.xver == 1 || reality.xver == 2) {
        std::array<uint8_t, 108> proxy_header{};
        const size_t proxy_header_len = EncodeProxyProtocolHeader(
            reality.xver,
            client_tcp->RemoteEndpoint(),
            client_tcp->LocalEndpoint(),
            proxy_header);
        first_ok = buf::AppendSpanToMultiBuffer(
            std::span<const uint8_t>(proxy_header.data(), proxy_header_len), first);
    }
    first_ok = first_ok && buf::AppendSpanToMultiBuffer(initial_bytes, first);
    memory::ByteVector{}.swap(initial_bytes);
    if (!first_ok) {
        dest_stream->CloseAbortive();
        client_tcp->CloseAbortive();
        co_return;
    }

    const auto idle_timeout = timeouts.IdleTimeout();
    const auto write_timeout = std::min(timeouts.WriteTimeout(), idle_timeout);
    client_tcp->ClearPhaseDeadline();
    for (AsyncStream* stream : {static_cast<AsyncStream*>(client_tcp.get()), dest_stream.get()}) {
        stream->SetIdleTimeout(idle_timeout);
        stream->SetReadTimeout(std::chrono::seconds(0));
        stream->SetWriteTimeout(write_timeout);
    }

    AsyncStream& client = *client_tcp;
    (void)co_await DoRelayLink(
        io_context,
        static_cast<transport::MultiBufferReader&>(client),
        static_cast<transport::MultiBufferWriter&>(client),
        &client,
        *dest_stream,
        ctx,
        fallback.stats,
        RelayConfig{
            .uplink_only = timeouts.UplinkOnlyTimeout(),
            .downlink_only = timeouts.DownlinkOnlyTimeout(),
        },
        buf::MultiBufferBatch(std::move(first)));
}

// Server TLS or REALITY layer. A REALITY ClientHello that fails
// authentication is relayed to the configured dest and yields a null stream.
net::awaitable<TransportBuildResult> AcceptInboundSecurity(
    net::io_context& io_context,
    std::unique_ptr<AsyncStream> stream,
    const StreamSettings& s,
    SslContext* ctx,
    const InboundFallbackContext* fallback,
    uint64_t conn_id) {
    if (!ctx) {
        LOG_CONN_ERROR(conn_id, "{} inbound security requires a Worker-owned server context",
                  s.IsReality() ? "REALITY" : "TLS");
        co_return tl::unexpected(ErrorCode::INVALID_ARGUMENT);
    }

    auto tcp = TakeOwnedTcpStream(stream);
    if (!tcp) {
        LOG_CONN_ERROR(conn_id, "inbound TLS security requires a TCP base stream");
        co_return tl::unexpected(ErrorCode::INVALID_ARGUMENT);
    }
    std::unique_ptr<RealityServerConnState> reality_conn_state;
    if (s.IsReality() && s.reality.HasDest()) {
        if (!fallback) {
            LOG_CONN_ERROR(conn_id, "REALITY dest fallback requires an inbound fallback context");
            co_return tl::unexpected(ErrorCode::INVALID_ARGUMENT);
        }
        memory::ByteVector initial_bytes;
        {
            // The caller's absolute phase deadline covers sniffing and SSL_accept;
            // never restart it when another record/fragment arrives.
            RealityClientHelloReader reader;
            buf::MultiBuffer pending;
            try {
                while (reader.State() == RealityClientHelloReader::Status::Reading) {
                    if (pending.empty()) {
                        pending = co_await tcp->ReadMultiBuffer();
                        if (pending.empty()) {
                            co_return tl::unexpected(ErrorCode::SOCKET_EOF);
                        }
                    }
                    const auto front = pending.FrontSpan();
                    const size_t take = std::min(front.size(), reader.ReadSize());
                    reader.Append(front.first(take));
                    pending.DropPrefixBytes(take);
                }
                for (size_t i = pending.size(); i > 0; --i) {
                    if (const buf::Buffer* b = *(pending.begin() + (i - 1));
                        b && !b->IsEmpty()) {
                        tcp->PrependReadData(b->Bytes());
                    }
                }
                pending.clear();
            } catch (...) {
                co_return tl::unexpected(ErrorCode::TLS_HANDSHAKE_FAILED);
            }
            if (reader.State() == RealityClientHelloReader::Status::Complete) {
                reality_conn_state = VerifyRealityClientHello(reader.Hello(), *ctx);
            }
            initial_bytes = reader.TakeWire();
        }
        if (!reality_conn_state) {
            LOG_CONN_DEBUG(conn_id,
                "REALITY server handshake unauthenticated; falling back to {}:{}",
                s.reality.dest_host,
                s.reality.dest_port);
            co_await RunRealityFallbackProxy(
                io_context,
                *fallback,
                std::move(tcp),
                s.reality,
                std::move(initial_bytes));
            co_return std::unique_ptr<AsyncStream>{};
        }
        tcp->PrependReadData(initial_bytes);
        memory::ByteVector{}.swap(initial_bytes);
    }
    std::unique_ptr<TlsStream> tls;
    if (reality_conn_state) {
        tls = std::make_unique<TlsStream>(std::move(tcp), *ctx, true);
        if (!tls->SetRealityServerPreverified(std::move(reality_conn_state))) {
            co_return tl::unexpected(ErrorCode::TLS_HANDSHAKE_FAILED);
        }
        if (!co_await tls->Handshake()) {
            tls.reset();
        }
    } else {
        tls = co_await WrapTlsServer(std::move(tcp), *ctx);
    }
    if (!tls) {
        LOG_CONN_DEBUG(conn_id, "{} server handshake failed",
                      s.IsReality() ? "REALITY" : "TLS");
        co_return tl::unexpected(ErrorCode::TLS_HANDSHAKE_FAILED);
    }
    LOG_CONN_DEBUG(conn_id, "{} server handshake completed",
                  s.IsReality() ? "REALITY" : "TLS");
    co_return std::unique_ptr<AsyncStream>(std::move(tls));
}

// Client TLS or REALITY layer shared by stream and XHTTP request builders.
net::awaitable<TransportBuildResult> ConnectOutboundSecurity(
    std::unique_ptr<AsyncStream> stream,
    const StreamSettings& s,
    SslContext* ctx,
    std::string_view sni,
    uint64_t conn_id) {
    if (!ctx) {
        LOG_CONN_ERROR(conn_id, "{} outbound security requires a Worker-owned client context",
                  s.IsReality() ? "REALITY" : "TLS");
        co_return tl::unexpected(ErrorCode::INVALID_ARGUMENT);
    }

    auto tcp = TakeOwnedTcpStream(stream);
    if (!tcp) {
        LOG_CONN_ERROR(conn_id, "outbound TLS security requires a TCP base stream");
        co_return tl::unexpected(ErrorCode::INVALID_ARGUMENT);
    }
    auto tls = s.IsReality()
        ? co_await WrapRealityClient(std::move(tcp), *ctx, s.reality, sni)
        : co_await WrapTlsClient(std::move(tcp), *ctx, sni);
    if (!tls) {
        LOG_CONN_DEBUG(conn_id, "{} client handshake failed (sni={})",
                      s.IsReality() ? "REALITY" : "TLS",
                      sni);
        co_return tl::unexpected(ErrorCode::TLS_HANDSHAKE_FAILED);
    }
    const std::string_view alpn = tls->NegotiatedAlpn();
    LOG_CONN_DEBUG(conn_id, "{} client handshake completed (sni={} alpn={})",
                  s.IsReality() ? "REALITY" : "TLS",
                  sni,
                  alpn.empty() ? std::string_view("-") : alpn);
    co_return std::unique_ptr<AsyncStream>(std::move(tls));
}

// HTTP/2 prior knowledge is recognized by the full client preface; anything
// else is served as HTTP/1 with the sniffed bytes as the start of the request.
net::awaitable<TransportBuildResult> DoHttpServerHandshake(
    std::unique_ptr<AsyncStream> stream,
    const HttpConfig& cfg,
    net::io_context& io_context,
    std::shared_ptr<InboundTransportStreamHandler> stream_handler,
    uint64_t conn_id,
    InboundTransportMetadata* transport_metadata,
    const XHttpConfig* xhttp_config) {
    using transport::internet::kHttp2ClientPreface;
    std::array<uint8_t, kHttp2ClientPreface.size()> first{};
    size_t total = 0;
    while (total < first.size()) {
        const size_t n = co_await stream->AsyncRead(
            net::buffer(first.data() + total, first.size() - total));
        if (n == 0) {
            co_return tl::unexpected(ErrorCode::SOCKET_EOF);
        }
        total += n;
        if (!kHttp2ClientPreface.starts_with(std::string_view(
                unsafe::ptr_cast<const char>(first.data()), total))) {
            break;
        }
    }

    if (std::string_view(unsafe::ptr_cast<const char>(first.data()), total) ==
        kHttp2ClientPreface) {
        co_return co_await transport::internet::RunHttp2ServerSession(
            std::move(stream),
            cfg,
            xhttp_config,
            io_context,
            std::move(stream_handler),
            conn_id);
    }

    const std::span<const uint8_t> initial(first.data(), total);
    if (xhttp_config) {
        co_return co_await transport::internet::DoXHttp1ServerHandshake(
            io_context,
            std::move(stream),
            cfg,
            *xhttp_config,
            conn_id,
            transport_metadata,
            initial,
            stream_handler);
    }
    co_return co_await transport::internet::DoHttp1ServerHandshake(
        std::move(stream), cfg, conn_id, transport_metadata, initial);
}

net::awaitable<TransportBuildResult> DoXHttp2PacketUpClientRequest(
    std::unique_ptr<AsyncStream> stream,
    const HttpConfig& cfg,
    std::string_view host,
    bool tls,
    std::span<const net::const_buffer> packet_payload,
    uint64_t conn_id) {
    auto upload = co_await transport::internet::DoHttp2ClientHandshake(
        std::move(stream), cfg, host, tls, conn_id);
    if (!upload) {
        co_return tl::unexpected(upload.error());
    }
    auto body = std::move(*upload);
    try {
        co_await body->WriteBuffers(packet_payload);
        co_await body->AsyncShutdownWrite();
        // Wait for the response so the packet is acknowledged before reuse.
        std::array<uint8_t, 1> scratch{};
        (void)co_await body->AsyncRead(net::buffer(scratch));
    } catch (...) {
        body->CloseAbortive();
        co_return tl::unexpected(ErrorCode::SOCKET_WRITE_FAILED);
    }
    body->Close();
    co_return std::unique_ptr<AsyncStream>{};
}

void LogLayerFailure(uint64_t conn_id, std::string_view layer, ErrorCode error) {
    LOG_CONN_DEBUG(conn_id, "{} failed > {}", layer, ErrorCodeToString(error));
}

}  // namespace

net::awaitable<TransportBuildResult> BuildInboundTransport(
    net::io_context& io_context,
    std::unique_ptr<AsyncStream> raw,
    const StreamSettings& s,
    SslContext* security_context,
    uint64_t trace_conn_id,
    std::shared_ptr<InboundTransportStreamHandler> stream_handler,
    InboundTransportMetadata* metadata,
    const InboundFallbackContext* fallback)
{
    std::unique_ptr<AsyncStream> stream = std::move(raw);
    const uint64_t conn_id = trace_conn_id;

    if (s.IsUnsupported() || !ReceivesSupportedReality(s)) {
        LOG_CONN_ERROR(conn_id, "unsupported inbound transport combination network={} security={}",
                  s.network,
                  s.security);
        co_return tl::unexpected(ErrorCode::PROTOCOL_UNSUPPORTED);
    }

    // 1. TLS / REALITY 层（服务端）
    if (s.IsTlsLike()) {
        auto secured = co_await AcceptInboundSecurity(
            io_context, std::move(stream), s, security_context, fallback, conn_id);
        if (!secured || !*secured) {
            co_return secured;
        }
        stream = std::move(*secured);
    }

    // 2. gRPC 层（服务端）
    if (s.IsGrpc()) {
        auto grpc_result = co_await transport::internet::DoGrpcServerHandshake(
            std::move(stream),
            s.grpc,
            io_context,
            std::move(stream_handler),
            conn_id);
        if (!grpc_result) {
            LogLayerFailure(conn_id, "gRPC server handshake", grpc_result.error());
            co_return tl::unexpected(grpc_result.error());
        }
        stream = std::move(*grpc_result);
    }

    // 3. HTTP / h2 层（服务端）
    if (s.IsHttp()) {
        auto http_result = co_await DoHttpServerHandshake(
            std::move(stream),
            s.http,
            io_context,
            std::move(stream_handler),
            conn_id,
            metadata,
            nullptr);
        if (!http_result) {
            LogLayerFailure(conn_id, "HTTP server handshake", http_result.error());
            co_return tl::unexpected(http_result.error());
        }
        stream = std::move(*http_result);
    }

    // 4. XHTTP 层（服务端：H2 stream-one 或 H1 packet-up）
    if (s.IsXHttp()) {
        // Outlives the HTTP/2 session, which borrows it until the call returns.
        const HttpConfig http = transport::internet::XHttpStreamOneHttpConfig(s.xhttp, false);
        auto xhttp_result = co_await DoHttpServerHandshake(
            std::move(stream),
            http,
            io_context,
            std::move(stream_handler),
            conn_id,
            metadata,
            &s.xhttp);
        if (!xhttp_result) {
            LogLayerFailure(conn_id, "XHTTP server handshake", xhttp_result.error());
            co_return tl::unexpected(xhttp_result.error());
        }
        stream = std::move(*xhttp_result);
    }

    // 5. WebSocket 层（服务端）
    if (s.IsWs()) {
        auto ws_result = co_await transport::internet::DoWsServerHandshake(
            std::move(stream), s.ws, conn_id, metadata);
        if (!ws_result) {
            LogLayerFailure(conn_id, "WebSocket server handshake", ws_result.error());
            co_return tl::unexpected(ws_result.error());
        }
        stream = std::move(*ws_result);
    }

    // 6. HTTPUpgrade 层（服务端）
    if (s.IsHttpUpgrade()) {
        auto http_upgrade_result = co_await transport::internet::DoHttpUpgradeServerHandshake(
            std::move(stream), s.http_upgrade, conn_id, metadata);
        if (!http_upgrade_result) {
            LogLayerFailure(conn_id, "HTTPUpgrade server handshake",
                            http_upgrade_result.error());
            co_return tl::unexpected(http_upgrade_result.error());
        }
        stream = std::move(*http_upgrade_result);
    }

    co_return stream;
}

net::awaitable<TransportBuildResult> BuildOutboundTransport(
    std::unique_ptr<AsyncStream> raw,
    const StreamSettings& s,
    SslContext* security_context,
    std::string_view tls_server_name,
    std::string_view ws_host,
    uint64_t trace_conn_id)
{
    std::unique_ptr<AsyncStream> stream = std::move(raw);
    const uint64_t conn_id = trace_conn_id;

    if (s.IsUnsupported() || !ReceivesSupportedReality(s)) {
        LOG_CONN_ERROR(conn_id, "unsupported outbound transport combination network={} security={}",
                  s.network,
                  s.security);
        co_return tl::unexpected(ErrorCode::PROTOCOL_UNSUPPORTED);
    }

    const std::string_view sni = tls_server_name.empty()
        ? (s.IsReality() && !s.reality.server_name.empty()
               ? std::string_view(s.reality.server_name)
               : std::string_view(s.tls.server_name))
        : tls_server_name;
    // Host for HTTP-based layers unless the transport config names one.
    const std::string_view dial_host = ws_host.empty() ? sni : ws_host;

    // 1. TLS / REALITY 层（客户端）
    if (s.IsTlsLike()) {
        auto secured = co_await ConnectOutboundSecurity(
            std::move(stream), s, security_context, sni, conn_id);
        if (!secured) {
            co_return secured;
        }
        stream = std::move(*secured);
    }

    // 2. gRPC 层（客户端）
    if (s.IsGrpc()) {
        std::string_view authority;
        if (!s.grpc.authority.empty()) {
            authority = s.grpc.authority;
        } else if (!s.IsReality()) {
            authority = dial_host;
        }
        auto grpc_result = co_await transport::internet::DoGrpcClientHandshake(
            std::move(stream), s.grpc, authority, s.IsTlsLike(), conn_id);
        if (!grpc_result) {
            LogLayerFailure(conn_id, "gRPC client handshake", grpc_result.error());
            co_return tl::unexpected(grpc_result.error());
        }
        stream = std::move(*grpc_result);
    }

    // 3. HTTP / h2 层（客户端）
    if (s.IsHttp()) {
        const std::string_view host = ResolveHttpAuthority(dial_host, s.http);
        auto http_result = ShouldUseHttp2ForHttp(s)
            ? co_await transport::internet::DoHttp2ClientHandshake(
                  std::move(stream), s.http, host, s.IsTlsLike(), conn_id)
            : co_await transport::internet::DoHttp1ClientHandshake(
                  std::move(stream), s.http, host, conn_id);
        if (!http_result) {
            LogLayerFailure(conn_id, "HTTP client handshake", http_result.error());
            co_return tl::unexpected(http_result.error());
        }
        stream = std::move(*http_result);
    }

    // 4. XHTTP stream-one 层（客户端，HTTP/2 raw body/response）
    if (s.IsXHttp()) {
        if (const XHttpMode mode = ResolveXHttpOutboundMode(s); mode != XHttpMode::StreamOne) {
            LOG_CONN_ERROR(conn_id, "XHTTP client {} requires the split dialer",
                      XHttpModeName(mode));
            co_return tl::unexpected(ErrorCode::PROTOCOL_UNSUPPORTED);
        }
        const HttpConfig http = transport::internet::XHttpStreamOneHttpConfig(s.xhttp, true);
        auto xhttp_result = co_await transport::internet::DoHttp2ClientHandshake(
            std::move(stream),
            http,
            ResolveHttpAuthority(dial_host, http),
            s.IsTlsLike(),
            conn_id);
        if (!xhttp_result) {
            LogLayerFailure(conn_id, "XHTTP client handshake", xhttp_result.error());
            co_return tl::unexpected(xhttp_result.error());
        }
        stream = std::move(*xhttp_result);
    }

    // 5. WebSocket 层（客户端）
    if (s.IsWs()) {
        auto ws = std::make_unique<WsClientStream>(std::move(stream), conn_id);
        auto ws_result = co_await ws->Handshake(
            dial_host,
            s.ws.path.empty() ? "/" : s.ws.path,
            &s.ws.headers);
        if (!ws_result) {
            LogLayerFailure(conn_id, "WebSocket client handshake", ws_result.error());
            co_return tl::unexpected(ws_result.error());
        }
        stream = std::move(ws);
    }

    // 6. HTTPUpgrade 层（客户端）
    if (s.IsHttpUpgrade()) {
        auto http_upgrade_result = co_await transport::internet::DoHttpUpgradeClientHandshake(
            std::move(stream), s.http_upgrade, dial_host, conn_id);
        if (!http_upgrade_result) {
            LogLayerFailure(conn_id, "HTTPUpgrade client handshake",
                            http_upgrade_result.error());
            co_return tl::unexpected(http_upgrade_result.error());
        }
        stream = std::move(*http_upgrade_result);
    }

    co_return stream;
}

net::awaitable<TransportBuildResult> BuildOutboundXHttpClientRequest(
    std::unique_ptr<AsyncStream> raw,
    const StreamSettings& s,
    SslContext* security_context,
    std::string_view tls_server_name,
    std::string_view host,
    std::string_view path,
    XHttpClientRequestKind kind,
    std::span<const net::const_buffer> packet_payload,
    uint64_t trace_conn_id) {
    if (!raw || !s.IsXHttp() || s.IsUnsupported()) {
        co_return tl::unexpected(ErrorCode::PROTOCOL_UNSUPPORTED);
    }

    const std::string_view sni = tls_server_name.empty()
        ? (s.IsReality() && !s.reality.server_name.empty()
               ? std::string_view(s.reality.server_name)
               : std::string_view(s.tls.server_name))
        : tls_server_name;
    std::unique_ptr<AsyncStream> stream = std::move(raw);
    if (s.IsTlsLike()) {
        auto secured = co_await ConnectOutboundSecurity(
            std::move(stream), s, security_context, sni, trace_conn_id);
        if (!secured) {
            co_return secured;
        }
        stream = std::move(*secured);
    }

    const HttpConfig http = transport::internet::XHttpClientHttpConfig(
        s.xhttp,
        path,
        kind == XHttpClientRequestKind::Downlink ? "GET" : "POST",
        s.IsTlsLike(),
        kind);

    std::string_view dial_host = host;
    if (dial_host.empty()) {
        dial_host = s.IsReality() && !s.reality.server_name.empty()
            ? std::string_view(s.reality.server_name)
            : sni;
    }
    const std::string_view authority = ResolveHttpAuthority(dial_host, http);

    if (!ShouldUseHttp2ForXHttp(s)) {
        co_return co_await transport::internet::DoXHttp1ClientRequest(
            std::move(stream), http, authority, kind, packet_payload, trace_conn_id);
    }
    if (kind == XHttpClientRequestKind::PacketUp) {
        co_return co_await DoXHttp2PacketUpClientRequest(
            std::move(stream), http, authority, s.IsTlsLike(), packet_payload, trace_conn_id);
    }
    auto http2_result = co_await transport::internet::DoHttp2ClientHandshake(
        std::move(stream), http, authority, s.IsTlsLike(), trace_conn_id);
    if (http2_result && kind == XHttpClientRequestKind::StreamUp && !packet_payload.empty()) {
        try {
            co_await (*http2_result)->WriteBuffers(packet_payload);
        } catch (...) {
            (*http2_result)->CloseAbortive();
            co_return tl::unexpected(ErrorCode::SOCKET_WRITE_FAILED);
        }
    }
    co_return http2_result;
}

