#include "acppnode/app/access_log_session.hpp"

#include <cassert>

int main() {
    using namespace acpp;

    session::Context ctx;
    ctx.outbound.target.type = AddressType::Domain;
    ctx.outbound.target.host = "www.example.com";
    ctx.outbound.target.port = 443;
    ctx.outbound.target.resolved_addr = net::ip::make_address("192.0.2.10");

    ctx.outbound.connected_target_addr = net::ip::make_address("192.0.2.20");
    ctx.outbound.connected_local_addr = net::ip::make_address("2001:db8::10");
    auto event = app::BuildAccessLogEvent(
        ctx, accesslog::CloseSide::Remote, 1, 2, ErrorCode::OK);
    assert(event.target_host == "www.example.com");
    assert(event.remote_ip == "192.0.2.20");
    assert(event.local_ip == "2001:db8::10");

    ctx.outbound.connected_target_addr = net::ip::address{};
    event = app::BuildAccessLogEvent(
        ctx, accesslog::CloseSide::Remote, 1, 2, ErrorCode::OK);
    assert(event.remote_ip.empty());

    ctx.outbound.connected_target_addr.reset();
    ctx.outbound.target.resolved_addr.reset();
    event = app::BuildAccessLogEvent(
        ctx, accesslog::CloseSide::Remote, 1, 2, ErrorCode::OK);
    assert(event.remote_ip.empty());
    assert(event.target_host == "www.example.com");

    ctx.outbound.target = TargetAddress(
        net::ip::make_address("198.51.100.7"), 8443);
    ctx.inbound.user_id = 1001;
    event = app::BuildAccessLogEvent(
        ctx, accesslog::CloseSide::Remote, 1, 2, ErrorCode::DIAL_REFUSED);
    assert(event.user_id == 1001);
    assert(event.target_host == "198.51.100.7");
    assert(event.target_port == 8443);
    assert(event.remote_ip.empty());

    event = app::BuildAccessLogEvent(
        ctx, accesslog::CloseSide::Unknown, 3, 4, ErrorCode::BLOCKED);
    assert(event.result == accesslog::Result::Rejected);
    assert(event.error_code == ErrorCode::BLOCKED);

    event = app::BuildAccessLogEvent(
        ctx, accesslog::CloseSide::Unknown, 5, 6, ErrorCode::CANCELLED);
    assert(event.result == accesslog::Result::Cancelled);
    assert(event.error_code == ErrorCode::CANCELLED);

    event = app::BuildAccessLogEvent(
        ctx, accesslog::CloseSide::Unknown, 7, 8, ErrorCode::DIAL_REFUSED);
    assert(event.result == accesslog::Result::Failed);
    assert(event.error_code == ErrorCode::DIAL_REFUSED);

    ctx.content.multiple_targets = true;
    ctx.outbound.connected_target_addr = net::ip::make_address("203.0.113.9");
    event = app::BuildAccessLogEvent(
        ctx, accesslog::CloseSide::Client, 9, 10, ErrorCode::OK);
    assert(event.target_host.empty());
    assert(event.target_port == 0);
    assert(event.remote_ip == "203.0.113.9");

    return 0;
}
