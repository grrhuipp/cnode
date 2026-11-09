#pragma once

#include "transport/internet/transport_stack.hpp"

#include <array>
#include <cstdint>
#include <memory>
#include <string_view>

namespace transport::internet {

inline constexpr std::string_view kHttp2ClientPreface =
    "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

[[nodiscard]] constexpr std::array<uint8_t, 6> EncodeInitialWindowSetting(
    uint32_t value) noexcept {
    return {{
        0,
        4,  // SETTINGS_INITIAL_WINDOW_SIZE
        static_cast<uint8_t>(value >> 24),
        static_cast<uint8_t>(value >> 16),
        static_cast<uint8_t>(value >> 8),
        static_cast<uint8_t>(value),
    }};
}
// Server receive policy (RFC 9113 5.2, 6.1, 6.9):
// - Body credit returns on logical consumption, not DATA arrival; padding and
//   discarded/reset bodies return connection credit without reopening streams.
// - The advertised stream window is capped at 4 MiB; the connection window is
//   8 MiB, so one stalled stream cannot stop an independent stream or controls.
// - Queued vector capacity is capped at 4 MiB per stream. A 16 MiB connection
//   reservation budget covers queue capacity and conservatively charged gRPC
//   assembly storage (excluding bounded container/allocator overhead).
// - gRPC assembly is a bounded internal consumer and advances credit for
//   fragmented messages larger than a stream window. Completed messages keep
//   their memory reservation until consumed or discarded.
// - XHTTP uploads retain their additional shared session budget.

// The read pump, logical requests, upload joins, close/reset work, and credit
// writer share the session's owned task group on the Worker reactor and join
// before return.
// gRPC server: reads the client preface, then serves the connection until it
// ends. Logical streams are delivered to `stream_handler`.
[[nodiscard]] net::awaitable<TransportBuildResult> DoGrpcServerHandshake(
    std::unique_ptr<AsyncStream> stream,
    const GrpcConfig& cfg,
    net::io_context& io_context,
    std::shared_ptr<InboundTransportStreamHandler> stream_handler,
    uint64_t conn_id);

// h2 / XHTTP server after the caller consumed the client preface. `cfg` and
// `xhttp_cfg` are borrowed for the whole call; the session never outlives it.
[[nodiscard]] net::awaitable<TransportBuildResult> RunHttp2ServerSession(
    std::unique_ptr<AsyncStream> stream,
    const HttpConfig& cfg,
    const XHttpConfig* xhttp_cfg,
    net::io_context& io_context,
    std::shared_ptr<InboundTransportStreamHandler> stream_handler,
    uint64_t conn_id);

[[nodiscard]] net::awaitable<TransportBuildResult> DoGrpcClientHandshake(
    std::unique_ptr<AsyncStream> stream,
    const GrpcConfig& cfg,
    std::string_view authority,
    bool tls,
    uint64_t conn_id);

[[nodiscard]] net::awaitable<TransportBuildResult> DoHttp2ClientHandshake(
    std::unique_ptr<AsyncStream> stream,
    const HttpConfig& cfg,
    std::string_view authority,
    bool tls,
    uint64_t conn_id);

}  // namespace transport::internet
