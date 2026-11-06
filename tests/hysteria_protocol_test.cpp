#include "hysteria_protocol.hpp"

#include <cassert>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

using acpp::transport::internet::hysteria::EncodeUdpMessage;
using acpp::transport::internet::hysteria::ParseUdpMessage;
using acpp::transport::internet::hysteria::ParseV1ClientHello;
using acpp::transport::internet::hysteria::ParseV1Request;
using acpp::transport::internet::hysteria::ParseV2TcpRequest;
using acpp::transport::internet::hysteria::UdpMessage;
using acpp::transport::internet::hysteria::Version;

namespace {

void TestV1HelloAndTcpRequest() {
    const std::vector<uint8_t> hello{
        3,
        0, 0, 0, 0, 0, 0, 0x03, 0xe8,
        0, 0, 0, 0, 0, 0, 0x07, 0xd0,
        0, 6, 's', 'e', 'c', 'r', 'e', 't'};
    const auto parsed_hello = ParseV1ClientHello(hello);
    assert(parsed_hello);
    assert(parsed_hello->send_bps == 1000);
    assert(parsed_hello->receive_bps == 2000);
    assert(parsed_hello->auth == "secret");

    const std::vector<uint8_t> request{
        0, 0, 11, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',
        0x01, 0xbb, 'p', 'a', 'y'};
    const auto parsed_request = ParseV1Request(request);
    assert(parsed_request);
    assert(!parsed_request->udp);
    assert(parsed_request->target.IsDomain());
    assert(parsed_request->target.host == "example.com");
    assert(parsed_request->target.port == 443);
    assert(parsed_request->header_bytes == request.size() - 3);
}

void TestV1UdpSessionRequestHasNoTarget() {
    const std::vector<uint8_t> request{1, 0, 0, 0, 0};
    const auto parsed = ParseV1Request(request);
    assert(parsed);
    assert(parsed->udp);
    assert(!parsed->target.IsValid());
    assert(parsed->header_bytes == request.size());
}

void TestV2TcpRequestWithReadAhead() {
    const std::vector<uint8_t> request{
        0x40, 0x01,  // QUIC varint 0x401
        0x09, '[', ':', ':', '1', ']', ':', '4', '4', '3',
        0x03, 0xaa, 0xbb, 0xcc,
        'x', 'y'};
    const auto parsed = ParseV2TcpRequest(request);
    assert(parsed);
    assert(parsed->target.IsIPv6());
    assert(parsed->target.port == 443);
    assert(parsed->header_bytes == request.size() - 2);
}

void TestV1UdpRoundTrip() {
    const std::vector<uint8_t> payload{'d', 'a', 't', 'a'};
    UdpMessage message;
    message.session_id = 0x01020304;
    message.packet_id = 42;
    message.target = acpp::TargetAddress("1.2.3.4", 53);
    message.payload = payload;
    const auto encoded = EncodeUdpMessage(Version::V1, message);
    assert(encoded);
    const auto parsed = ParseUdpMessage(Version::V1, *encoded);
    assert(parsed);
    assert(parsed->session_id == message.session_id);
    assert(parsed->packet_id == message.packet_id);
    assert(parsed->target.SameEndpoint(message.target));
    assert(parsed->payload.size() == payload.size());
}

void TestV2UdpRoundTripAndContinuationFragment() {
    const std::vector<uint8_t> payload{'d', 'n', 's'};
    UdpMessage message;
    message.session_id = 7;
    message.packet_id = 99;
    message.fragment_id = 0;
    message.fragment_count = 2;
    message.target = acpp::TargetAddress("example.com", 53);
    message.payload = payload;
    const auto encoded = EncodeUdpMessage(Version::V2, message);
    assert(encoded);
    const auto parsed = ParseUdpMessage(Version::V2, *encoded);
    assert(parsed);
    assert(parsed->target.SameEndpoint(message.target));

    message.fragment_id = 1;
    message.target = {};
    const auto continuation = EncodeUdpMessage(Version::V2, message);
    assert(continuation);
    const auto parsed_continuation = ParseUdpMessage(Version::V2, *continuation);
    assert(parsed_continuation);
    assert(!parsed_continuation->target.IsValid());
}

void TestRejectsMalformedFragments() {
    const std::vector<uint8_t> invalid{
        0, 0, 0, 1, 0, 1, 2, 2, 0, 'x'};
    assert(!ParseUdpMessage(Version::V2, invalid));
}

}  // namespace

int main() {
    TestV1HelloAndTcpRequest();
    TestV1UdpSessionRequestHasNoTarget();
    TestV2TcpRequestWithReadAhead();
    TestV1UdpRoundTrip();
    TestV2UdpRoundTripAndContinuationFragment();
    TestRejectsMalformedFragments();
}
