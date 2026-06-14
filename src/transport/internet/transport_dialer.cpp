#include "acppnode/transport/internet/transport_dialer.hpp"
#include "acppnode/common/session.hpp"
#include "acppnode/transport/internet/tcp_stream.hpp"
#include "acppnode/transport/internet/transport_stack.hpp"
#include "acppnode/infra/log.hpp"

#include <span>
#include <string>

namespace acpp {

namespace {

net::awaitable<DialResult> DialSingleCandidate(
    net::io_context& io_context,
    const OutboundTransportTarget& target,
    const OutboundDialCandidate& candidate) {

    auto bind_local = candidate.bind_local;

    DialResult tcp_result;
    if (bind_local) {
        tcp_result = co_await TcpStream::ConnectWithBind(
            io_context, *bind_local, candidate.endpoint, target.timeout);
    } else {
        tcp_result = co_await TcpStream::Connect(
            io_context, candidate.endpoint, target.timeout);
    }

    co_return tcp_result;
}

net::awaitable<DialResult> DialCandidatesSequential(
    net::io_context& io_context,
    const OutboundTransportTarget& target,
    std::span<const OutboundDialCandidate> candidates) {

    DialResult last_result =
        DialResult::Fail(ErrorCode::DIAL_CONNECT_FAILED, "all dial candidates failed");

    for (const auto& candidate : candidates) {
        auto attempt = co_await DialSingleCandidate(
            io_context, target, candidate);
        if (attempt.Ok()) {
            co_return attempt;
        }

        LOG_DEBUG("DialOutboundTransport: connect {}:{} failed: {}",
                  candidate.endpoint.address().to_string(),
                  candidate.endpoint.port(),
                  attempt.error_msg);
        last_result = std::move(attempt);
    }

    co_return last_result;
}

}  // namespace

net::awaitable<DialResult> DialOutboundTransport(
    net::io_context& io_context,
    session::Context& ctx,
    const OutboundTransportTarget& target) {

    if ((!target.single_candidate && target.candidates.empty()) || target.stream_settings == nullptr) {
        co_return DialResult::Fail(ErrorCode::INVALID_ARGUMENT, "invalid outbound transport target");
    }

    DialResult tcp_result =
        DialResult::Fail(ErrorCode::DIAL_CONNECT_FAILED, "all dial candidates failed");
    if (target.single_candidate) {
        tcp_result = co_await DialSingleCandidate(
            io_context, target, *target.single_candidate);
    } else if (target.candidates.size() == 1) {
        tcp_result = co_await DialSingleCandidate(
            io_context, target, target.candidates.front());
    } else {
        tcp_result = co_await DialCandidatesSequential(
            io_context, target, target.candidates);
    }

    if (!tcp_result.Ok()) {
        co_return tcp_result;
    }

    tcp_result.stream->SetIdleTimeout(target.timeout);
    (void)tcp_result.stream->StartPhaseDeadline(target.timeout);

    auto build_result = co_await BuildOutboundTransport(
        std::move(tcp_result.stream),
        *target.stream_settings,
        target.server_name,
        ctx.conn_id);
    if (!build_result) {
        const ErrorCode code = build_result.error();
        co_return DialResult::Fail(
            code,
            std::string("outbound transport build failed: ") + std::string(ErrorCodeToString(code)));
    }
    auto stream = std::move(*build_result);

    stream->ClearPhaseDeadline();
    // 后续 outbound handler / relay 阶段会重新设置 idle/read/write timeout。
    stream->SetIdleTimeout(std::chrono::seconds(0));

    co_return DialResult::Success(std::move(stream));
}

}  // namespace acpp
