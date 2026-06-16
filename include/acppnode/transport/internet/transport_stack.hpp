#pragma once

#include "acppnode/transport/async_stream.hpp"
#include "acppnode/transport/internet/stream_settings.hpp"
#include <expected>
#include <memory>
#include <span>
#include <string_view>

namespace acpp {

using TransportBuildResult = std::expected<std::unique_ptr<AsyncStream>, ErrorCode>;

class InboundTransportStreamHandler {
public:
    virtual ~InboundTransportStreamHandler() noexcept = default;
    virtual void OnInboundTransportStream(std::unique_ptr<AsyncStream> stream) = 0;
};

// 根据 StreamSettings 将原始 TCP 流包装成最终传输流。
// 协议层调用 Process()/Handshake() 前，传入的流已经完成 TLS/WS。
net::awaitable<TransportBuildResult> BuildInboundTransport(
    net::io_context& io_context,
    std::unique_ptr<AsyncStream> raw,
    const StreamSettings& s,
    std::string* out_real_ip = nullptr,
    uint64_t trace_conn_id = 0,
    std::shared_ptr<InboundTransportStreamHandler> stream_handler = nullptr);

net::awaitable<TransportBuildResult> BuildOutboundTransport(
    std::unique_ptr<AsyncStream> raw,
    const StreamSettings& s,
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
    std::string_view tls_server_name,
    std::string_view host,
    std::string_view path,
    XHttpClientRequestKind kind,
    std::span<const net::const_buffer> packet_payload = {},
    uint64_t trace_conn_id = 0);

}  // namespace acpp
