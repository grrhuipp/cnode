#pragma once

#include "common/asio_types.hpp"
#include "transport/async_stream.hpp"
#include "transport/internet/dial_target.hpp"


namespace session {
struct Context;
}

// 统一出站传输连接：
// 消费冷路径预构建候选，建立 TCP 连接，并按 StreamSettings 完成 TLS/WS。
[[nodiscard]]
net::awaitable<DialResult> DialOutboundTransport(
    net::io_context& io_context,
    session::Context& ctx,
    const OutboundTransportTarget& target);

