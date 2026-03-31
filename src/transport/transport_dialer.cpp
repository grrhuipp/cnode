#include "acppnode/transport/transport_dialer.hpp"
#include "acppnode/common/allocator.hpp"
#include "acppnode/common/ip_utils.hpp"
#include "acppnode/transport/tcp_stream.hpp"
#include "acppnode/infra/log.hpp"

#include <string>
#include <unordered_set>

namespace acpp {

namespace {

const StreamSettings kDefaultStreamSettings = [] {
    StreamSettings s;
    s.RecomputeModes();
    return s;
}();
struct TcpConnectAttemptResult {
    DialResult dial;
    tcp::endpoint endpoint;
};

bool ShouldRetryWithoutBind(
    OutboundTransportTarget::BindMode bind_mode,
    bool attempted_bind,
    ErrorCode error) {
    if (!attempted_bind || bind_mode != OutboundTransportTarget::BindMode::Auto) {
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

std::vector<OutboundDialCandidate> DeduplicateCandidates(
    std::vector<OutboundDialCandidate> candidates) {
    std::unordered_set<std::string> seen;
    std::vector<OutboundDialCandidate> unique;
    unique.reserve(candidates.size());

    for (auto& candidate : candidates) {
        const auto key = candidate.endpoint.address().to_string();
        if (seen.insert(key).second) {
            unique.push_back(std::move(candidate));
        }
    }

    return unique;
}

cobalt::task<std::expected<std::vector<OutboundDialCandidate>, ErrorCode>> ResolveCandidates(
    net::any_io_executor executor,
    const OutboundTransportTarget& target) {

    if (!target.candidates.empty()) {
        std::vector<OutboundDialCandidate> filtered;
        filtered.reserve(target.candidates.size());
        for (const auto& candidate : target.candidates) {
            if (candidate.endpoint.address().is_v4()) {
                filtered.push_back(candidate);
            }
        }
        co_return DeduplicateCandidates(std::move(filtered));
    }

    boost::system::error_code ec;
    auto addr = net::ip::make_address(target.host, ec);
    if (!ec) {
        if (!addr.is_v4()) {
            co_return std::unexpected(ErrorCode::PROTOCOL_INVALID_ADDRESS);
        }
        co_return std::vector<OutboundDialCandidate>{
            OutboundDialCandidate{tcp::endpoint(addr, target.port), target.bind_local}
        };
    }

    try {
        tcp::resolver resolver(executor);
        auto results = co_await resolver.async_resolve(
            target.host,
            std::to_string(target.port),
            cobalt::use_op);
        if (results.empty()) {
            co_return std::unexpected(ErrorCode::DNS_RESOLVE_FAILED);
        }

        std::vector<OutboundDialCandidate> candidates;
        for (const auto& result : results) {
            if (!result.endpoint().address().is_v4()) {
                continue;
            }
            candidates.push_back(
                OutboundDialCandidate{result.endpoint(), target.bind_local});
        }
        co_return DeduplicateCandidates(std::move(candidates));
    } catch (...) {
        co_return std::unexpected(ErrorCode::DNS_RESOLVE_FAILED);
    }
}

cobalt::task<TcpConnectAttemptResult> DialSingleCandidate(
    net::any_io_executor executor,
    const OutboundTransportTarget& target,
    const OutboundDialCandidate& candidate,
    bool use_target_bind_fallback) {

    auto bind_local = candidate.bind_local;
    if (!bind_local && use_target_bind_fallback) {
        bind_local = target.bind_local;
    }

    DialResult tcp_result;
    if (bind_local) {
        tcp_result = co_await TcpStream::ConnectWithBind(
            executor, *bind_local, candidate.endpoint, target.timeout);
        if (!tcp_result.Ok() && ShouldRetryWithoutBind(
                target.bind_mode, true, tcp_result.error)) {
            LOG_WARN("TransportDialer: auto bind {} -> {}:{} failed ({}), retrying with system bind",
                     bind_local->to_string(),
                     candidate.endpoint.address().to_string(),
                     candidate.endpoint.port(),
                     tcp_result.error_msg);
            tcp_result = co_await TcpStream::Connect(
                executor, candidate.endpoint, target.timeout);
        }
    } else {
        tcp_result = co_await TcpStream::Connect(
            executor, candidate.endpoint, target.timeout);
    }

    co_return TcpConnectAttemptResult{std::move(tcp_result), candidate.endpoint};
}

cobalt::task<TcpConnectAttemptResult> DialCandidatesSequential(
    net::any_io_executor executor,
    const OutboundTransportTarget& target,
    const std::vector<OutboundDialCandidate>& candidates,
    bool use_target_bind_fallback) {

    TcpConnectAttemptResult last_result{
        DialResult::Fail(ErrorCode::DIAL_CONNECT_FAILED, "all dial candidates failed"),
        {}
    };

    for (const auto& candidate : candidates) {
        auto attempt = co_await DialSingleCandidate(
            executor, target, candidate, use_target_bind_fallback);
        if (attempt.dial.Ok()) {
            co_return attempt;
        }

        LOG_DEBUG("TransportDialer: connect {}:{} failed: {}",
                  candidate.endpoint.address().to_string(),
                  candidate.endpoint.port(),
                  attempt.dial.error_msg);
        last_result = std::move(attempt);
    }

    co_return last_result;
}

}  // namespace

cobalt::task<DialResult> TransportDialer::Dial(
    net::any_io_executor executor,
    SessionContext& ctx,
    const OutboundTransportTarget& target) {

    if ((target.host.empty() && target.candidates.empty()) || target.port == 0) {
        co_return DialResult::Fail(ErrorCode::INVALID_ARGUMENT, "invalid outbound transport target");
    }

    auto candidates_result = co_await ResolveCandidates(executor, target);
    if (!candidates_result) {
        co_return DialResult::Fail(candidates_result.error(), "resolve outbound endpoint failed");
    }
    auto candidates = std::move(*candidates_result);
    if (candidates.empty()) {
        co_return DialResult::Fail(ErrorCode::DNS_RESOLVE_FAILED, "no outbound dial candidates");
    }

    const bool use_target_bind_fallback = target.candidates.empty();
    auto connect_result = co_await DialCandidatesSequential(
        executor, target, candidates, use_target_bind_fallback);

    if (!connect_result.dial.Ok()) {
        co_return std::move(connect_result.dial);
    }
    auto tcp_result = std::move(connect_result.dial);
    ctx.resolved_ip = iputil::NormalizeAddress(connect_result.endpoint.address());

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
        ctx.local_ip = iputil::NormalizeAddress(local_ep->address());
    }

    co_return DialResult::Success(std::move(stream));
}

}  // namespace acpp
