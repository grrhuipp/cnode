#include "acppnode/transport/transport_dialer.hpp"
#include "acppnode/transport/tcp_stream.hpp"
#include "acppnode/infra/log.hpp"

#include <string>

namespace acpp {

namespace {

const StreamSettings kDefaultStreamSettings = [] {
    StreamSettings s;
    s.RecomputeModes();
    return s;
}();

bool ShouldRetryWithoutBind(const OutboundTransportTarget& target, ErrorCode error) {
    if (!target.bind_local || target.bind_mode != OutboundTransportTarget::BindMode::Auto) {
        return false;
    }

    switch (error) {
        case ErrorCode::SOCKET_BIND_FAILED:
        case ErrorCode::DIAL_NETWORK_UNREACHABLE:
        case ErrorCode::DIAL_HOST_UNREACHABLE:
            return true;
        default:
            return false;
    }
}

cobalt::task<std::expected<tcp::endpoint, ErrorCode>> ResolveEndpoint(
    net::any_io_executor executor,
    std::string_view host,
    uint16_t port) {

    boost::system::error_code ec;
    auto addr = net::ip::make_address(host, ec);
    if (!ec) {
        co_return tcp::endpoint(addr, port);
    }

    try {
        tcp::resolver resolver(executor);
        auto results = co_await resolver.async_resolve(
            std::string(host),
            std::to_string(port),
            cobalt::use_op);
        if (results.empty()) {
            co_return std::unexpected(ErrorCode::DNS_RESOLVE_FAILED);
        }
        co_return results.begin()->endpoint();
    } catch (...) {
        co_return std::unexpected(ErrorCode::DNS_RESOLVE_FAILED);
    }
}

}  // namespace

cobalt::task<DialResult> TransportDialer::Dial(
    net::any_io_executor executor,
    SessionContext& ctx,
    const OutboundTransportTarget& target) {

    if (target.host.empty() || target.port == 0) {
        co_return DialResult::Fail(ErrorCode::INVALID_ARGUMENT, "invalid outbound transport target");
    }

    auto endpoint_result = co_await ResolveEndpoint(executor, target.host, target.port);
    if (!endpoint_result) {
        co_return DialResult::Fail(endpoint_result.error(), "resolve outbound endpoint failed");
    }
    auto endpoint = *endpoint_result;
    ctx.resolved_ip = endpoint.address();

    DialResult tcp_result;
    if (target.bind_local) {
        tcp_result = co_await TcpStream::ConnectWithBind(
            executor, *target.bind_local, endpoint, target.timeout);
        if (!tcp_result.Ok() && ShouldRetryWithoutBind(target, tcp_result.error_code)) {
            LOG_WARN("TransportDialer: auto bind {} -> {}:{} failed ({}), retrying with system bind",
                     target.bind_local->to_string(),
                     endpoint.address().to_string(),
                     endpoint.port(),
                     tcp_result.error_msg);
            tcp_result = co_await TcpStream::Connect(
                executor, endpoint, target.timeout);
        }
    } else {
        tcp_result = co_await TcpStream::Connect(
            executor, endpoint, target.timeout);
    }

    if (!tcp_result.Ok()) {
        co_return tcp_result;
    }

    tcp_result.stream->SetIdleTimeout(target.timeout);
    auto transport_deadline = tcp_result.stream->StartPhaseDeadline(target.timeout);

    const StreamSettings& stream_settings =
        target.stream_settings ? *target.stream_settings : kDefaultStreamSettings;

    auto build_result = co_await TransportStack::BuildOutbound(
        std::move(tcp_result.stream),
        stream_settings,
        target.server_name);
    if (!build_result) {
        const ErrorCode code = transport_deadline.Expired()
            ? ErrorCode::TIMEOUT
            : build_result.error();
        co_return DialResult::Fail(
            code,
            std::string("outbound transport build failed: ") + std::string(ErrorCodeToString(code)));
    }
    auto stream = std::move(*build_result);

    stream->ClearPhaseDeadline();
    // 后续阶段由 SessionHandler 重新设置 idle/read/write timeout
    stream->SetIdleTimeout(std::chrono::seconds(0));
    if (auto local_ep = stream->LocalEndpoint()) {
        ctx.local_ip = local_ep->address();
    }

    co_return DialResult::Success(std::move(stream));
}

}  // namespace acpp
