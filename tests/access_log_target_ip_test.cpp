#include "acppnode/app/access_log_session.hpp"
#include "acppnode/common/read_prefix_capture.hpp"

#include <algorithm>
#include <cassert>
#include <memory>
#include <string>

int main() {
    using namespace acpp;

    session::Context ctx;
    ctx.outbound.target.type = AddressType::Domain;
    ctx.outbound.target.host = "www.example.com";
    ctx.outbound.target.port = 443;
    ctx.outbound.target.resolved_addr = net::ip::make_address("192.0.2.10");

    ctx.outbound.connected_target_addr = net::ip::make_address("192.0.2.20");
    ctx.outbound.dial_target_addr = net::ip::make_address("192.0.2.10");
    ctx.outbound.connected_local_addr = net::ip::make_address("2001:db8::10");
    auto event = app::BuildAccessLogEvent(
        ctx, accesslog::CloseSide::Remote, 1, 2, ErrorCode::OK);
    assert(event.target_host == "www.example.com");
    assert(event.remote_ip == "192.0.2.20");
    assert(event.dial_ip == "192.0.2.10");
    assert(event.local_ip == "2001:db8::10");

    ctx.outbound.connected_target_addr = net::ip::address{};
    event = app::BuildAccessLogEvent(
        ctx, accesslog::CloseSide::Remote, 1, 2, ErrorCode::OK);
    assert(event.remote_ip.empty());

    ctx.outbound.connected_target_addr.reset();
    ctx.outbound.dial_target_addr = net::ip::make_address("198.51.100.8");
    ctx.outbound.target.resolved_addr.reset();
    event = app::BuildAccessLogEvent(
        ctx, accesslog::CloseSide::Remote, 1, 2, ErrorCode::OK);
    assert(event.remote_ip.empty());
    assert(event.dial_ip == "198.51.100.8");
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
    assert(event.dial_ip == "198.51.100.8");

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
    assert(event.failure_stage == "dial");

    const std::string http =
        "GET / HTTP/1.1\r\nHost: example.com\r\nAuthorization: Bearer secret\r\n\r\n";
    ctx.inbound.protocol = "http";
    ctx.inbound.read_prefix_capture = std::make_shared<ReadPrefixCapture>();
    ctx.inbound.read_prefix_capture->Append(std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(http.data()), http.size()));
    event = app::BuildAccessLogEvent(
        ctx, accesslog::CloseSide::Unknown, 0, 0, ErrorCode::PROTOCOL_AUTH_FAILED);
    assert(event.raw_packet_original_len == http.size());
    assert(event.raw_packet_captured_len == http.size());
    assert(event.raw_packet_protocol_guess == "http");
    assert(event.raw_packet_redacted);
    assert(event.raw_packet_sha256.size() == 64);
    const std::string redacted(event.raw_packet.begin(), event.raw_packet.end());
    assert(redacted.find("secret") == std::string::npos);

    ctx.content.multiple_targets = true;
    ctx.outbound.connected_target_addr = net::ip::make_address("203.0.113.9");
    ctx.outbound.dial_target_addr = net::ip::address{};
    event = app::BuildAccessLogEvent(
        ctx, accesslog::CloseSide::Client, 9, 10, ErrorCode::OK);
    assert(event.target_host.empty());
    assert(event.target_port == 0);
    assert(event.remote_ip == "203.0.113.9");
    assert(event.dial_ip.empty());

    return 0;
}
