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
    auto event = app::BuildAccessLogEvent(
        ctx, accesslog::CloseSide::Remote, 1, 2);
    assert(event.target_host == "www.example.com");
    assert(event.remote_ip == "192.0.2.20");

    ctx.outbound.connected_target_addr = net::ip::address{};
    event = app::BuildAccessLogEvent(
        ctx, accesslog::CloseSide::Remote, 1, 2);
    assert(event.remote_ip == "192.0.2.10");

    ctx.outbound.connected_target_addr.reset();
    ctx.outbound.target.resolved_addr.reset();
    event = app::BuildAccessLogEvent(
        ctx, accesslog::CloseSide::Remote, 1, 2);
    assert(event.remote_ip.empty());
    assert(event.target_host == "www.example.com");

    return 0;
}
