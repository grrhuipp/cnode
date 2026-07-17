#include "acppnode/app/access_log_session.hpp"

#include "acppnode/common/clock.hpp"
#include "acppnode/common/ip_utils.hpp"
#include "acppnode/common/network.hpp"

#include <algorithm>

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

std::string AddressString(const net::ip::address& address) {
    if (address.is_unspecified()) {
        return {};
    }
    return iputil::NormalizeAddressString(address);
}

accesslog::Result ToAccessResult(ErrorCode error_code) noexcept {
    switch (error_code) {
        case ErrorCode::OK:
            return accesslog::Result::Completed;
        case ErrorCode::CANCELLED:
            return accesslog::Result::Cancelled;
        case ErrorCode::PERMISSION_DENIED:
        case ErrorCode::PROTOCOL_AUTH_FAILED:
        case ErrorCode::ROUTER_NO_MATCH:
        case ErrorCode::ROUTER_OUTBOUND_NOT_FOUND:
        case ErrorCode::BLOCKED:
        case ErrorCode::VMESS_INVALID_USER:
        case ErrorCode::PANEL_USER_DISABLED:
        case ErrorCode::PANEL_TRAFFIC_EXCEEDED:
            return accesslog::Result::Rejected;
        default:
            return accesslog::Result::Failed;
    }
}

}  // namespace

accesslog::Event BuildAccessLogEvent(
    const session::Context& ctx,
    accesslog::CloseSide close_side,
    uint64_t bytes_up,
    uint64_t bytes_down,
    ErrorCode error_code) {
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

    if (ctx.outbound.connected_target_addr) {
        event.remote_ip = AddressString(*ctx.outbound.connected_target_addr);
    }
    if (ctx.outbound.connected_local_addr) {
        event.local_ip = AddressString(*ctx.outbound.connected_local_addr);
    }
    if (event.target_host.empty()) {
        event.target_host = event.remote_ip;
    }

    event.uplink_bytes = std::max(bytes_up, ctx.traffic.bytes_up);
    event.downlink_bytes = std::max(bytes_down, ctx.traffic.bytes_down);
    event.result = ToAccessResult(error_code);
    event.error_code = error_code;
    event.close_side = close_side;
    event.dns_state = static_cast<uint8_t>(ctx.content.dns_result);
    event.sniff_protocol = ctx.content.protocol;
    event.sniff_domain = ctx.content.sniff_domain;
    return event;
}

}  // namespace acpp::app
