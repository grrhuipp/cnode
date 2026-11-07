#include <gtest/gtest.h>

#include "hysteria_protocol.hpp"

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

TEST(HysteriaProtocol, V1HelloAndTcpRequest) {
    const std::vector<uint8_t> hello{
        3,
        0, 0, 0, 0, 0, 0, 0x03, 0xe8,
        0, 0, 0, 0, 0, 0, 0x07, 0xd0,
        0, 6, 's', 'e', 'c', 'r', 'e', 't'};
    const auto parsed_hello = ParseV1ClientHello(hello);
    ASSERT_TRUE(parsed_hello);
    ASSERT_TRUE(parsed_hello->send_bps == 1000);
    ASSERT_TRUE(parsed_hello->receive_bps == 2000);
    ASSERT_TRUE(parsed_hello->auth == "secret");

    const std::vector<uint8_t> request{
        0, 0, 11, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',
        0x01, 0xbb, 'p', 'a', 'y'};
    const auto parsed_request = ParseV1Request(request);
    ASSERT_TRUE(parsed_request);
    ASSERT_TRUE(!parsed_request->udp);
    ASSERT_TRUE(parsed_request->target.IsDomain());
    ASSERT_TRUE(parsed_request->target.host == "example.com");
    ASSERT_TRUE(parsed_request->target.port == 443);
    ASSERT_TRUE(parsed_request->header_bytes == request.size() - 3);
}

TEST(HysteriaProtocol, V1UdpSessionRequestHasNoTarget) {
    const std::vector<uint8_t> request{1, 0, 0, 0, 0};
    const auto parsed = ParseV1Request(request);
    ASSERT_TRUE(parsed);
    ASSERT_TRUE(parsed->udp);
    ASSERT_TRUE(!parsed->target.IsValid());
    ASSERT_TRUE(parsed->header_bytes == request.size());
}

TEST(HysteriaProtocol, V2TcpRequestWithReadAhead) {
    const std::vector<uint8_t> request{
        0x44, 0x01,  // QUIC varint 0x401
        0x09, '[', ':', ':', '1', ']', ':', '4', '4', '3',
        0x03, 0xaa, 0xbb, 0xcc,
        'x', 'y'};
    const auto parsed = ParseV2TcpRequest(request);
    ASSERT_TRUE(parsed);
    ASSERT_TRUE(parsed->target.IsIPv6());
    ASSERT_TRUE(parsed->target.port == 443);
    ASSERT_TRUE(parsed->header_bytes == request.size() - 2);
}

TEST(HysteriaProtocol, V1UdpRoundTrip) {
    const std::vector<uint8_t> payload{'d', 'a', 't', 'a'};
    UdpMessage message;
    message.session_id = 0x01020304;
    message.packet_id = 42;
    message.target = acpp::TargetAddress("1.2.3.4", 53);
    message.payload = payload;
    const auto encoded = EncodeUdpMessage(Version::V1, message);
    ASSERT_TRUE(encoded);
    const auto parsed = ParseUdpMessage(Version::V1, *encoded);
    ASSERT_TRUE(parsed);
    ASSERT_TRUE(parsed->session_id == message.session_id);
    ASSERT_TRUE(parsed->packet_id == message.packet_id);
    ASSERT_TRUE(parsed->target.SameEndpoint(message.target));
    ASSERT_TRUE(parsed->payload.size() == payload.size());
}

TEST(HysteriaProtocol, V2UdpRoundTripAndContinuationFragment) {
    const std::vector<uint8_t> payload{'d', 'n', 's'};
    UdpMessage message;
    message.session_id = 7;
    message.packet_id = 99;
    message.fragment_id = 0;
    message.fragment_count = 2;
    message.target = acpp::TargetAddress("example.com", 53);
    message.payload = payload;
    const auto encoded = EncodeUdpMessage(Version::V2, message);
    ASSERT_TRUE(encoded);
    const auto parsed = ParseUdpMessage(Version::V2, *encoded);
    ASSERT_TRUE(parsed);
    ASSERT_TRUE(parsed->target.SameEndpoint(message.target));

    message.fragment_id = 1;
    message.target = {};
    const auto continuation = EncodeUdpMessage(Version::V2, message);
    ASSERT_TRUE(continuation);
    const auto parsed_continuation = ParseUdpMessage(Version::V2, *continuation);
    ASSERT_TRUE(parsed_continuation);
    ASSERT_TRUE(!parsed_continuation->target.IsValid());
}

TEST(HysteriaProtocol, RejectsMalformedFragments) {
    const std::vector<uint8_t> invalid{
        0, 0, 0, 1, 0, 1, 2, 2, 0, 'x'};
    ASSERT_TRUE(!ParseUdpMessage(Version::V2, invalid));
}

}  // namespace

