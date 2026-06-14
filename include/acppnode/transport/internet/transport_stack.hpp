#pragma once

#include "acppnode/transport/async_stream.hpp"
#include "acppnode/transport/internet/stream_settings.hpp"
#include <expected>
#include <memory>
#include <string_view>

namespace acpp {

using TransportBuildResult = std::expected<std::unique_ptr<AsyncStream>, ErrorCode>;

// 根据 StreamSettings 将原始 TCP 流包装成最终传输流。
// 协议层调用 Process()/Handshake() 前，传入的流已经完成 TLS/WS。
net::awaitable<TransportBuildResult> BuildInboundTransport(
    std::unique_ptr<AsyncStream> raw,
    const StreamSettings& s,
    std::string* out_real_ip = nullptr,
    uint64_t trace_conn_id = 0);

net::awaitable<TransportBuildResult> BuildOutboundTransport(
    std::unique_ptr<AsyncStream> raw,
    const StreamSettings& s,
    std::string_view server_name = {},
    uint64_t trace_conn_id = 0);

}  // namespace acpp
