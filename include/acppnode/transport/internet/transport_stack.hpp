#pragma once

#include "acppnode/transport/async_stream.hpp"
#include "acppnode/transport/internet/proxy_protocol.hpp"
#include "acppnode/transport/internet/stream_settings.hpp"
#include <tl/expected.hpp>
#include <memory>
#include <span>
#include <string_view>

namespace acpp {
class SslContext;
namespace app::dns {
class DNS;
}  // namespace app::dns


using TransportBuildResult = tl::expected<std::unique_ptr<AsyncStream>, ErrorCode>;

struct InboundTransportMetadata {
    memory::ThreadLocalString real_ip;
    memory::ThreadLocalString real_ip_header;
};
class InboundTransportStreamHandler {
public:
    virtual ~InboundTransportStreamHandler() noexcept = default;
    virtual net::awaitable<void> OnInboundTransportStream(
        std::unique_ptr<AsyncStream> stream, InboundTransportMetadata metadata) = 0;
    virtual void OnInboundTransportReady(AsyncStream&) {}
    // A persistent HTTP/1 connection began its next request, which gets a
    // fresh transport handshake budget; OnInboundTransportReady ends it.
    virtual void OnInboundTransportRequest(AsyncStream&) {}
};


// Detect and consume a PROXY v1/v2 prefix, preserving ordinary application
// bytes. The caller decides whether an absent header is allowed (auto) or
// rejected (on); malformed headers and incomplete reads fail in either mode.
net::awaitable<ProxyProtocolReadResult> ReadInboundProxyProtocol(
    AsyncStream& raw,
    std::chrono::seconds timeout);

// 根据 StreamSettings 将原始 TCP 流包装成最终传输流。|security_context| is
// the owning handler's TransportSecurity::Context(): borrowed for the call,
// required exactly when the settings use TLS or REALITY.
net::awaitable<TransportBuildResult> BuildInboundTransport(
    net::io_context& io_context,
    std::unique_ptr<AsyncStream> raw,
    const StreamSettings& s,
    SslContext* security_context,
    uint64_t trace_conn_id = 0,
    std::shared_ptr<InboundTransportStreamHandler> stream_handler = nullptr,
    InboundTransportMetadata* metadata = nullptr,
    app::dns::DNS* dns_service = nullptr);

net::awaitable<TransportBuildResult> BuildOutboundTransport(
    std::unique_ptr<AsyncStream> raw,
    const StreamSettings& s,
    SslContext* security_context,
    std::string_view tls_server_name = {},
    std::string_view ws_host = {},
    uint64_t trace_conn_id = 0);

enum class XHttpClientRequestKind {
    Downlink,
    StreamUp,
    PacketUp,
};

net::awaitable<TransportBuildResult> BuildOutboundXHttpClientRequest(
    std::unique_ptr<AsyncStream> raw,
    const StreamSettings& s,
    SslContext* security_context,
    std::string_view tls_server_name,
    std::string_view host,
    std::string_view path,
    XHttpClientRequestKind kind,
    std::span<const net::const_buffer> packet_payload = {},
    uint64_t trace_conn_id = 0);

}  // namespace acpp
