#include "acppnode/app/access_log_session.hpp"

#include "acppnode/common/clock.hpp"
#include "acppnode/common/ip_utils.hpp"
#include "acppnode/common/network.hpp"

#include <algorithm>
#include <string_view>

namespace acpp::app {

namespace {

accesslog::Network ToAccessNetwork(::acpp::Network network) noexcept {
    switch (network) {
        case ::acpp::Network::TCP:
            return accesslog::Network::Tcp;
        case ::acpp::Network::UDP:
            return accesslog::Network::Udp;
        case ::acpp::Network::MUX:
            return accesslog::Network::Mux;
        default:
            return accesslog::Network::Unknown;
    }
}

bool IsRejectedError(ErrorCode error) noexcept {
    switch (error) {
        case ErrorCode::PERMISSION_DENIED:
        case ErrorCode::RESOURCE_EXHAUSTED:
        case ErrorCode::PROTOCOL_AUTH_FAILED:
        case ErrorCode::BLOCKED:
        case ErrorCode::VMESS_INVALID_USER:
        case ErrorCode::VMESS_REPLAY_ATTACK:
        case ErrorCode::PANEL_USER_DISABLED:
        case ErrorCode::PANEL_TRAFFIC_EXCEEDED:
            return true;
        default:
            return false;
    }
}

std::string AddressString(const net::ip::address& address) {
    if (address.is_unspecified()) {
        return {};
    }
    return iputil::NormalizeAddressString(address);
}

}  // namespace

accesslog::Event BuildAccessLogEvent(
    const session::Context& ctx,
    accesslog::Result result,
    ErrorCode error,
    accesslog::CloseSide close_side,
    uint64_t bytes_up,
    uint64_t bytes_down) {
    accesslog::Event event;
    event.source_ref = ctx.inbound.access_source_ref;
    event.conn_id = ctx.conn_id;
    event.worker_id = ctx.worker_id;
    event.user_id = ctx.inbound.user_id;
    event.started_at_unix_us = ctx.accept_time_us;
    event.ended_at_unix_us = NowMicros();
    if (event.ended_at_unix_us > event.started_at_unix_us) {
        event.duration_ms = static_cast<uint64_t>(
            (event.ended_at_unix_us - event.started_at_unix_us) / 1000);
    }

    event.user_email = ctx.inbound.user_email;
    event.inbound_tag.assign(ctx.inbound.tag);
    event.outbound_tag.assign(ctx.outbound.tag);
    event.protocol.assign(ctx.inbound.protocol);
    event.network = ToAccessNetwork(ctx.content.network);

    event.source_ip = ctx.inbound.source_ip.empty()
        ? AddressString(ctx.inbound.source_addr)
        : ctx.inbound.source_ip;
    event.source_port = ctx.inbound.source_port;

    const TargetAddress& target = ctx.outbound.target;
    event.target_host = target.host;
    event.target_port = target.port;
    if (target.resolved_addr) {
        event.remote_ip = AddressString(*target.resolved_addr);
        if (event.target_host.empty()) {
            event.target_host = event.remote_ip;
        }
    }

    event.uplink_bytes = std::max(bytes_up, ctx.traffic.bytes_up);
    event.downlink_bytes = std::max(bytes_down, ctx.traffic.bytes_down);
    event.result = result;
    event.error_code = error;
    event.close_side = close_side;
    event.dns_state = static_cast<uint8_t>(ctx.content.dns_result);
    event.sniff_protocol = ctx.content.protocol;
    event.sniff_domain = ctx.content.sniff_domain;
    return event;
}

AccessLogSession::AccessLogSession(session::Context& ctx) noexcept
    : ctx_(&ctx) {}

AccessLogSession::~AccessLogSession() noexcept {
    if (!ctx_ || cancelled_ || ctx_->access_event_submitted ||
        ctx_->inbound.access_source_ref == 0) {
        return;
    }

    ctx_->access_event_submitted = true;
    try {
        (void)accesslog::Reporter::Instance().Submit(BuildAccessLogEvent(
            *ctx_, result_, error_, close_side_, bytes_up_, bytes_down_));
    } catch (...) {
        // Reporting is fail-open and must never unwind into the proxy path.
    }
}

void AccessLogSession::Complete(const RelayResult& result) noexcept {
    bytes_up_ = result.bytes_up;
    bytes_down_ = result.bytes_down;
    error_ = result.error;
    close_side_ = result.client_closed_first
        ? accesslog::CloseSide::Client
        : accesslog::CloseSide::Remote;

    if (result.error == ErrorCode::OK) {
        result_ = accesslog::Result::Completed;
    } else if (result.error == ErrorCode::CANCELLED) {
        result_ = accesslog::Result::Cancelled;
    } else if (IsRejectedError(result.error)) {
        result_ = accesslog::Result::Rejected;
    } else {
        result_ = accesslog::Result::Failed;
    }
}

void AccessLogSession::Reject(ErrorCode error) noexcept {
    result_ = accesslog::Result::Rejected;
    error_ = error;
}

void AccessLogSession::Fail(ErrorCode error) noexcept {
    result_ = error == ErrorCode::CANCELLED
        ? accesslog::Result::Cancelled
        : accesslog::Result::Failed;
    error_ = error;
}

void AccessLogSession::Cancel() noexcept {
    cancelled_ = true;
    if (ctx_) {
        ctx_->access_event_submitted = true;
    }
}

}  // namespace acpp::app
