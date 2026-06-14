#pragma once

#include "acppnode/common/asio_types.hpp"
#include "acppnode/transport/async_stream.hpp"
#include "acppnode/transport/internet/dial_target.hpp"

namespace acpp {

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

}  // namespace acpp
