#pragma once

#include "common/error.hpp"
#include "common/target_address.hpp"
#include "transport/async_stream.hpp"
#include "transport/proxy_protocol.hpp"
#include "transport/stream_settings.hpp"

#include <tl/expected.hpp>

#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace app {

class GroupCoordinator;
struct StatsShard;
class DNSWorker;

}  // namespace app
namespace infra {

struct TimeoutsConfig;

}  // namespace infra
namespace common {
struct Context;
}  // namespace common

namespace transport {

// 传输层构建结果：成功时为最终传输流；入站把请求交给 InboundTransportStreamHandler
// 后返回空流。
using TransportBuildResult = tl::expected<std::unique_ptr<AsyncStream>, common::ErrorCode>;

// 入站传输握手期间从请求中提取、随逻辑流交给入站处理的元数据。
struct InboundTransportMetadata {
    std::string real_ip;
    // 传输层已识别的原生 UDP 会话的首个目标；有值即该逻辑流是 UDP 会话（Network::UDP）。
    std::optional<common::TargetAddress> udp_session_target;
};

class SslContext;
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

// REALITY dest fallback stays in the transport layer (as in Xray) but reuses
// the shared dial path, relay, stats and timeouts. Every member is borrowed
// for the BuildInboundTransport call. |ctx| is the accepted connection's
// unauthenticated session: it only carries conn id/logging and the relay byte
// counters; it never reaches dispatch, routing or user accounting. The
// caller's physical admission reservation must outlive the call, which then
// covers the whole fallback relay.
struct InboundFallbackContext {
    common::Context& ctx;
    app::StatsShard& stats;
    const infra::TimeoutsConfig& timeouts;
    app::DNSWorker* dns_service = nullptr;
};


// Detect and consume a PROXY v1/v2 prefix, preserving ordinary application
// bytes. The caller decides whether an absent header is allowed (auto) or
// rejected (on); malformed headers and incomplete reads fail in either mode.
net::awaitable<ProxyProtocolReadResult> ReadInboundProxyProtocol(
    AsyncStream& raw,
    std::chrono::seconds timeout);

// 根据 StreamSettings 将原始 TCP 流包装成最终传输流。|security_context| is
// the owning handler's TransportSecurity::Context(): borrowed for the call,
// required exactly when the settings use TLS or REALITY. |fallback| is
// required for REALITY with dest; an unauthenticated ClientHello is then
// relayed to dest and the call yields a null stream.
net::awaitable<TransportBuildResult> BuildInboundTransport(
    app::GroupCoordinator& coordinator,
    net::io_context& io_context,
    std::unique_ptr<AsyncStream> raw,
    const StreamSettings& s,
    SslContext* security_context,
    uint64_t trace_conn_id = 0,
    std::shared_ptr<InboundTransportStreamHandler> stream_handler = nullptr,
    InboundTransportMetadata* metadata = nullptr,
    const InboundFallbackContext* fallback = nullptr);

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

}  // namespace transport

