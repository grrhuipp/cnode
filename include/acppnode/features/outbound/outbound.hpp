#pragma once

#include "acppnode/app/relay_types.hpp"
#include "acppnode/app/udp_types.hpp"
#include "acppnode/common/asio_types.hpp"
#include "acppnode/common/buf/multi_buffer.hpp"
#include "acppnode/infra/runtime_config_types.hpp"
#include "acppnode/transport/link.hpp"

#include <chrono>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>

namespace acpp {
class AsyncStream;
namespace session {
struct Context;
}
}  // namespace acpp

namespace acpp::features::outbound {

// ============================================================================
// Handler - outbound feature handler interface
//
// 对齐 xray-core features/outbound.Handler 的资源边界：dispatcher 只持有
// outbound.Handler 抽象并调用 Dispatch，具体 proxyman handler 再绑定
// sender/transport/proxy.Outbound。
// ============================================================================
class Handler {
public:
    virtual ~Handler() noexcept = default;

    [[nodiscard]] virtual std::string_view Tag() const noexcept = 0;

    [[nodiscard]] virtual net::awaitable<std::optional<RelayResult>> Dispatch(
        net::io_context& io_context,
        const tcp::endpoint* inbound_local_addr,
        session::Context& ctx,
        const TimeoutsConfig& timeouts,
        transport::Link inbound_link,
        const RelayConfig& relay_config,
        std::span<const uint8_t> initial_payload,
        buf::MultiBuffer& first_payload,
        std::chrono::seconds relay_idle_timeout,
        std::chrono::seconds relay_write_timeout) = 0;

    [[nodiscard]] virtual net::awaitable<RelayResult> DispatchMux(
        net::io_context& io_context,
        AsyncStream& inbound_stream,
        session::Context& ctx,
        const UDPRelayConfig& relay_config) = 0;

    // datagram UDP 拨号：返回 Worker 的 UDPSession*（nullptr=失败/不支持）。
    // 仅服务原生 SS UDP 监听与 Mux UDP 子会话；UDP-over-TCP 隧道走 Dispatch。
    [[nodiscard]] virtual net::awaitable<UDPSession*> DispatchUDP(
        session::Context& ctx) = 0;

};

// ============================================================================
// Manager - outbound feature manager interface
// ============================================================================
class Manager {
public:
    virtual ~Manager() noexcept = default;

    [[nodiscard]] virtual Handler* GetHandler(std::string_view tag) noexcept = 0;
    [[nodiscard]] virtual Handler* GetDefaultHandler() noexcept = 0;
};

}  // namespace acpp::features::outbound
