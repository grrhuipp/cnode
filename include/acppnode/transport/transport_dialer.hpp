#pragma once

#include "acppnode/common.hpp"
#include "acppnode/common/error.hpp"
#include "acppnode/protocol/outbound.hpp"
#include "acppnode/transport/transport_stack.hpp"

namespace acpp {

// ============================================================================
// TransportDialer - 统一出站传输构建器
//
// 职责：
//   1. 解析 OutboundTransportTarget.host:port
//   2. 建立 TCP 连接（可选 bind_local）
//   3. 按 StreamSettings 构建传输层堆栈（TLS / WS）
// ============================================================================
class TransportDialer {
public:
    [[nodiscard]]
    static cobalt::task<DialResult> Dial(
        net::any_io_executor executor,
        SessionContext& ctx,
        const OutboundTransportTarget& target);
};

}  // namespace acpp

