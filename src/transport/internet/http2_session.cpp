#include "transport/internet/http2_session.hpp"
#include "transport/internet/h2_frame.hpp"
#include "transport/internet/http1_handshake.hpp"
#include "common/unsafe.hpp"
#include "infra/log.hpp"

#include <array>

namespace transport::internet {
using namespace h2;

net::awaitable<TransportBuildResult> DoGrpcServerHandshake(
    app::GroupCoordinator& coordinator,
    std::unique_ptr<AsyncStream> stream,
    const GrpcConfig& cfg,
    net::io_context& io_context,
    std::shared_ptr<InboundTransportStreamHandler> stream_handler,
    uint64_t conn_id) {
    std::array<uint8_t, kHttp2ClientPreface.size()> preface{};
    if (!co_await ReadFullFromStream(*stream, preface) ||
        std::string_view(unsafe::ptr_cast<const char>(preface.data()), preface.size()) !=
            kHttp2ClientPreface) {
        LOG_CONN_DEBUG(conn_id, "gRPC server received invalid HTTP/2 client preface");
        co_return tl::unexpected(common::ErrorCode::PROTOCOL_DECODE_FAILED);
    }

    co_return co_await StartHttp2ServerSession(coordinator, 
        std::move(stream),
        cfg.initial_window_size.value_or(kDefaultInitialWindow),
        H2PayloadCodec::GrpcHunk,
        io_context,
        std::move(stream_handler),
        conn_id,
        nullptr,
        nullptr,
        &cfg);
}

net::awaitable<TransportBuildResult> RunHttp2ServerSession(
    app::GroupCoordinator& coordinator,
    std::unique_ptr<AsyncStream> stream,
    const HttpConfig& cfg,
    const XHttpConfig* xhttp_cfg,
    net::io_context& io_context,
    std::shared_ptr<InboundTransportStreamHandler> stream_handler,
    uint64_t conn_id) {
    return StartHttp2ServerSession(coordinator, 
        std::move(stream),
        cfg.initial_window_size.value_or(kDefaultInitialWindow),
        H2PayloadCodec::RawData,
        io_context,
        std::move(stream_handler),
        conn_id,
        &cfg,
        xhttp_cfg,
        nullptr);
}

net::awaitable<TransportBuildResult> DoGrpcClientHandshake(
    std::unique_ptr<AsyncStream> stream,
    const GrpcConfig& cfg,
    std::string_view authority,
    bool tls,
    uint64_t conn_id) {
    const std::string_view path = cfg.request_path;
    const auto headers = EncodeGrpcRequestHeaders(
        authority,
        path,
        tls,
        cfg.user_agent.empty() ? std::string_view("grpc-go/1.0")
                               : std::string_view(cfg.user_agent));
    co_return co_await OpenHttp2ClientStream(
        std::move(stream),
        cfg.initial_window_size,
        headers,
        H2PayloadCodec::GrpcHunk,
        false,
        "gRPC",
        authority,
        path,
        conn_id);
}

net::awaitable<TransportBuildResult> DoHttp2ClientHandshake(
    std::unique_ptr<AsyncStream> stream,
    const HttpConfig& cfg,
    std::string_view authority,
    bool tls,
    uint64_t conn_id) {
    const auto headers = EncodeHttpRequestHeaders(authority, tls, cfg);
    const bool end_stream = common::EqualsAsciiCI(cfg.method, "GET");
    co_return co_await OpenHttp2ClientStream(
        std::move(stream),
        cfg.initial_window_size,
        headers,
        H2PayloadCodec::RawData,
        end_stream,
        "HTTP/2",
        authority,
        detail::EffectiveHttpPath(cfg.path),
        conn_id);
}

}  // namespace transport::internet
