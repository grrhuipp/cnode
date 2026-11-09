#pragma once

#include "common/asio_types.hpp"
#include "common/initial_payload.hpp"
#include "common/error.hpp"
#include "proxy/sniff_config.hpp"
#include "transport/link.hpp"

#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
#include <variant>


class AsyncStream;

namespace session {
struct Context;
}

struct StatsShard;
struct TimeoutsConfig;

namespace routing {

// Dispatcher-owned outbound selection policy. Both alternatives require an
// explicit target, so a receiver cannot accidentally inherit mutable process
// state or enter the hot path without a complete selection policy.
struct ForceOutbound {
    explicit ForceOutbound(std::string tag)
        : outbound_tag(std::move(tag)) {
        if (outbound_tag.empty()) {
            throw std::invalid_argument("forced outbound tag must not be empty");
        }
    }

    std::string outbound_tag;
};

struct RouteWithFallback {
    explicit RouteWithFallback(std::string tag)
        : outbound_tag(std::move(tag)) {
        if (outbound_tag.empty()) {
            throw std::invalid_argument("routing fallback tag must not be empty");
        }
    }

    std::string outbound_tag;
};

using OutboundSelectionPolicy = std::variant<ForceOutbound, RouteWithFallback>;

// Immutable after receiver preparation. Inbound handlers, Mux children and
// native UDP sessions pass only this narrow hot-path contract to Dispatcher.
struct DispatchPolicy {
    SniffConfig sniffing;
    OutboundSelectionPolicy outbound;
};

// ============================================================================
// Dispatcher - routing feature interface
//
// Dispatch 接收协议层准备好的不可变策略、transport::Link、初始 payload
// 和 relay 参数；路由编排是实现细节，唯一公开热路径直接进入
// outbound.Process 和 relay。
// ============================================================================
class Dispatcher {
public:
    virtual ~Dispatcher() noexcept = default;

    virtual net::awaitable<RelayResult> Dispatch(
        net::io_context& io_context,
        const DispatchPolicy& policy,
        std::unique_ptr<AsyncStream> inbound,
        transport::Link inbound_link,
        InitialPayload first_packet,
        session::Context& ctx,
        StatsShard& stats,
        const TimeoutsConfig& timeouts) = 0;
};

}  // namespace routing
