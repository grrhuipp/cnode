#include <gtest/gtest.h>

#include "hysteria_protocol.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <iterator>
#include <span>
#include <string_view>
#include <vector>

using ::transport::internet::hysteria::EncodeUdpMessage;
using ::transport::internet::hysteria::ParseUdpMessage;
using ::transport::internet::hysteria::ParseV1ClientHello;
using ::transport::internet::hysteria::ParseV1Request;
using ::transport::internet::hysteria::ParseV2TcpRequest;
using ::transport::internet::hysteria::UdpMessage;
using ::transport::internet::hysteria::Version;

namespace {

constexpr uint8_t kV2SinglePacket[]{
    0, 0, 0, 7, 0x12, 0x34, 255, 1, 14,
    'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', ':', '5', '3',
    'd', 'n', 's'};

class HysteriaProtocol : public ::testing::Test {
private:
    memory::AllocationDomain domain_;
    memory::ScopedAllocationDomain lease_{domain_};
};

TEST_F(HysteriaProtocol, V1HelloAndTcpRequest) {
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

TEST_F(HysteriaProtocol, V1UdpSessionRequestHasNoTarget) {
    const std::vector<uint8_t> request{1, 0, 0, 0, 0};
    const auto parsed = ParseV1Request(request);
    ASSERT_TRUE(parsed);
    ASSERT_TRUE(parsed->udp);
    ASSERT_TRUE(!parsed->target.IsValid());
    ASSERT_TRUE(parsed->header_bytes == request.size());
}

TEST_F(HysteriaProtocol, V2TcpRequestWithReadAhead) {
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

TEST_F(HysteriaProtocol, V1UdpRoundTrip) {
    const std::vector<uint8_t> payload{'d', 'a', 't', 'a'};
    UdpMessage message;
    message.session_id = 0x01020304;
    message.packet_id = 42;
    message.target = ::TargetAddress("1.2.3.4", 53);
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

TEST_F(HysteriaProtocol, V2UdpRoundTripAndContinuationFragment) {
    const std::vector<uint8_t> payload{'d', 'n', 's'};
    UdpMessage message;
    message.session_id = 7;
    message.packet_id = 99;
    message.fragment_id = 0;
    message.fragment_count = 2;
    message.target = ::TargetAddress("example.com", 53);
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

TEST_F(HysteriaProtocol, RejectsMalformedFragments) {
    const std::vector<uint8_t> invalid{
        0, 0, 0, 1, 0, 1, 2, 2, 0, 'x'};
    ASSERT_TRUE(!ParseUdpMessage(Version::V2, invalid));
}

TEST_F(HysteriaProtocol, V2SinglePacketAcceptsIgnoredFragmentId) {
    const auto parsed = ParseUdpMessage(Version::V2, kV2SinglePacket);
    ASSERT_TRUE(parsed);
    EXPECT_EQ(parsed->session_id, 7u);
    EXPECT_EQ(parsed->packet_id, 0x1234);
    EXPECT_EQ(parsed->fragment_id, 255);
    EXPECT_EQ(parsed->fragment_count, 1);
    EXPECT_TRUE(parsed->target.SameEndpoint(::TargetAddress("example.com", 53)));
    EXPECT_EQ(std::vector<uint8_t>(parsed->payload.begin(), parsed->payload.end()),
              (std::vector<uint8_t>{'d', 'n', 's'}));
}

TEST_F(HysteriaProtocol, V2SinglePacketEncodesIgnoredFragmentId) {
    const std::vector<uint8_t> payload{'d', 'n', 's'};
    const UdpMessage message{.session_id = 7, .packet_id = 0x1234,
        .fragment_id = 255, .fragment_count = 1,
        .target = ::TargetAddress("example.com", 53), .payload = payload};
    const auto encoded = EncodeUdpMessage(Version::V2, message);
    ASSERT_TRUE(encoded);
    EXPECT_TRUE(std::ranges::equal(*encoded, kV2SinglePacket));
}

TEST_F(HysteriaProtocol, V2FragmentCountAndIndexRemainValidated) {
    const std::vector<uint8_t> payload{'d', 'n', 's'};
    for (const uint8_t count : {uint8_t{0}, uint8_t{2}}) {
        SCOPED_TRACE(static_cast<unsigned>(count));
        auto wire = std::vector<uint8_t>(
            std::begin(kV2SinglePacket), std::end(kV2SinglePacket));
        wire[7] = count;
        const auto parsed = ParseUdpMessage(Version::V2, wire);
        ASSERT_FALSE(parsed);
        EXPECT_EQ(parsed.error(), ::transport::internet::hysteria::ProtocolError::Invalid);
        const UdpMessage message{.session_id = 7, .packet_id = 0x1234,
            .fragment_id = 255, .fragment_count = count,
            .target = ::TargetAddress("example.com", 53), .payload = payload};
        EXPECT_FALSE(EncodeUdpMessage(Version::V2, message));
    }
}

TEST_F(HysteriaProtocol, V2SinglePacketRequiresTargetRegardlessOfFragmentId) {
    const std::vector<uint8_t> wire{0, 0, 0, 7, 0x12, 0x34, 255, 1, 0, 'x'};
    const auto parsed = ParseUdpMessage(Version::V2, wire);
    ASSERT_FALSE(parsed);
    EXPECT_EQ(parsed.error(), ::transport::internet::hysteria::ProtocolError::Invalid);
    const std::vector<uint8_t> payload{'x'};
    const UdpMessage message{.session_id = 7, .packet_id = 0x1234,
        .fragment_id = 255, .fragment_count = 1, .target = {}, .payload = payload};
    EXPECT_FALSE(EncodeUdpMessage(Version::V2, message));
}

TEST_F(HysteriaProtocol, UdpPreservesEmptyAndMaximumPayloadsAcrossAddressForms) {
    using ::transport::internet::hysteria::kMaxUdpPayloadLength;
    using ::transport::internet::hysteria::UdpMessageHeaderSize;
    const auto domain = std::string(63, 'a') + "." + std::string(63, 'b') +
        "." + std::string(63, 'c') + "." + std::string(61, 'd');
    const std::array targets{
        ::TargetAddress("192.0.2.123", 65535),
        ::TargetAddress("2001:db8::1234", 65535),
        ::TargetAddress(domain, 65535)};
    std::array<uint8_t, kMaxUdpPayloadLength + 1> payload{};
    for (size_t i = 0; i < payload.size(); ++i) payload[i] = static_cast<uint8_t>(i);
    for (const auto version : {Version::V1, Version::V2}) {
        for (const auto& target : targets) {
            for (const size_t size : {size_t{0}, size_t{1}, kMaxUdpPayloadLength}) {
                const UdpMessage message{.session_id = 0x12345678, .packet_id = 0x8765,
                    .target = target, .payload = std::span(payload).first(size)};
                const auto encoded = EncodeUdpMessage(version, message);
                ASSERT_TRUE(encoded);
                const auto header = UdpMessageHeaderSize(version, target);
                ASSERT_TRUE(header);
                EXPECT_EQ(encoded->size(), *header + size);
                const auto parsed = ParseUdpMessage(version, *encoded);
                ASSERT_TRUE(parsed);
                EXPECT_EQ(parsed->session_id, message.session_id);
                EXPECT_EQ(parsed->packet_id, message.packet_id);
                EXPECT_TRUE(parsed->target.SameEndpoint(target));
                EXPECT_TRUE(std::ranges::equal(parsed->payload, message.payload));
            }
            const UdpMessage oversized{.target = target, .payload = payload};
            const auto rejected = EncodeUdpMessage(version, oversized);
            ASSERT_FALSE(rejected);
            EXPECT_EQ(rejected.error(),
                ::transport::internet::hysteria::ProtocolError::Invalid);
        }
    }
}

TEST_F(HysteriaProtocol, HandshakeResponsesKeepTheirWireEncoding) {
    using namespace ::transport::internet::hysteria;
    const std::vector<uint8_t> hello{
        1, 1, 2, 3, 4, 5, 6, 7, 8, 8, 7, 6, 5, 4, 3, 2, 1, 0, 2, 'o', 'k'};
    EXPECT_EQ(EncodeV1ServerHello(
        true, 0x0102030405060708ULL, 0x0807060504030201ULL, "ok"), hello);
    const std::vector<uint8_t> response{0, 0x12, 0x34, 0x56, 0x78, 0, 2, 'n', 'o'};
    EXPECT_EQ(EncodeV1Response(false, 0x12345678, "no"), response);
    const std::string message(64, 'm');
    const std::array<uint8_t, 2> padding{0xaa, 0xbb};
    std::vector<uint8_t> tcp{0, 0x40, 0x40};
    tcp.insert(tcp.end(), message.begin(), message.end());
    tcp.insert(tcp.end(), {2, 0xaa, 0xbb});
    EXPECT_EQ(EncodeV2TcpResponse(true, message, padding), tcp);
}

}  // namespace

