#include <gtest/gtest.h>

#include "transport/hysteria_wire.hpp"
#include <algorithm>
#include <array>
#include <cstdint>
#include <iterator>
#include <optional>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

using ::transport::ParseUdpMessage;
using ::transport::ParseV1ClientHello;
using ::transport::ParseV1Request;
using ::transport::ParseV2TcpRequest;
using UdpMessage = ::transport::HysteriaUdpMessage;
using Version = ::transport::HysteriaVersion;

namespace {

struct EncodedUdp {
    std::vector<uint8_t> wire;
    size_t header_size = 0;
};

// The production send path: format the target once, size the header, encode
// one fragment.
std::optional<EncodedUdp> EncodeUdp(Version version, const UdpMessage& message) {
    std::optional<::common::AddressText> address_storage;
    const auto text = ::transport::PrepareUdpTargetText(version, message.target, address_storage);
    if (!text) return std::nullopt;
    const auto header_size = ::transport::UdpTargetHeaderSize(version, *text);
    if (!header_size) return std::nullopt;
    auto wire = ::transport::EncodeUdpFragment(version, message, *text, *header_size);
    if (!wire) return std::nullopt;
    return EncodedUdp{std::move(*wire), *header_size};
}

constexpr uint8_t kV2SinglePacket[]{
    0, 0, 0, 7, 0x12, 0x34, 255, 1, 14,
    'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', ':', '5', '3',
    'd', 'n', 's'};

class HysteriaProtocol : public ::testing::Test {};

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
    message.target = ::common::TargetAddress("1.2.3.4", 53);
    message.payload = payload;
    const auto encoded = EncodeUdp(Version::V1, message);
    ASSERT_TRUE(encoded);
    const auto parsed = ParseUdpMessage(Version::V1, encoded->wire);
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
    message.target = ::common::TargetAddress("example.com", 53);
    message.payload = payload;
    const auto encoded = EncodeUdp(Version::V2, message);
    ASSERT_TRUE(encoded);
    const auto parsed = ParseUdpMessage(Version::V2, encoded->wire);
    ASSERT_TRUE(parsed);
    ASSERT_TRUE(parsed->target.SameEndpoint(message.target));

    message.fragment_id = 1;
    message.target = {};
    const auto continuation = EncodeUdp(Version::V2, message);
    ASSERT_TRUE(continuation);
    const auto parsed_continuation = ParseUdpMessage(Version::V2, continuation->wire);
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
    EXPECT_TRUE(parsed->target.SameEndpoint(::common::TargetAddress("example.com", 53)));
    EXPECT_EQ(std::vector<uint8_t>(parsed->payload.begin(), parsed->payload.end()),
              (std::vector<uint8_t>{'d', 'n', 's'}));
}

TEST_F(HysteriaProtocol, V2SinglePacketEncodesIgnoredFragmentId) {
    const std::vector<uint8_t> payload{'d', 'n', 's'};
    const UdpMessage message{.session_id = 7, .packet_id = 0x1234,
        .fragment_id = 255, .fragment_count = 1,
        .target = ::common::TargetAddress("example.com", 53), .payload = payload};
    const auto encoded = EncodeUdp(Version::V2, message);
    ASSERT_TRUE(encoded);
    EXPECT_TRUE(std::ranges::equal(encoded->wire, kV2SinglePacket));
}

TEST_F(HysteriaProtocol, V2FragmentCountAndIndexRemainValidated) {
    for (const uint8_t count : {uint8_t{0}, uint8_t{2}}) {
        SCOPED_TRACE(static_cast<unsigned>(count));
        auto wire = std::vector<uint8_t>(
            std::begin(kV2SinglePacket), std::end(kV2SinglePacket));
        wire[7] = count;
        const auto parsed = ParseUdpMessage(Version::V2, wire);
        ASSERT_FALSE(parsed);
        EXPECT_EQ(parsed.error(), ::transport::ProtocolError::Invalid);
    }
}

TEST_F(HysteriaProtocol, V2SinglePacketRequiresTargetRegardlessOfFragmentId) {
    const std::vector<uint8_t> wire{0, 0, 0, 7, 0x12, 0x34, 255, 1, 0, 'x'};
    const auto parsed = ParseUdpMessage(Version::V2, wire);
    ASSERT_FALSE(parsed);
    EXPECT_EQ(parsed.error(), ::transport::ProtocolError::Invalid);
}

TEST_F(HysteriaProtocol, UdpPreservesEmptyAndMaximumPayloadsAcrossAddressForms) {
    using ::transport::kMaxUdpPayloadLength;
    const auto domain = std::string(63, 'a') + "." + std::string(63, 'b') +
        "." + std::string(63, 'c') + "." + std::string(61, 'd');
    const std::array targets{
        ::common::TargetAddress("192.0.2.123", 65535),
        ::common::TargetAddress("2001:db8::1234", 65535),
        ::common::TargetAddress(domain, 65535)};
    std::array<uint8_t, kMaxUdpPayloadLength> payload{};
    for (size_t i = 0; i < payload.size(); ++i) payload[i] = static_cast<uint8_t>(i);
    for (const auto version : {Version::V1, Version::V2}) {
        for (const auto& target : targets) {
            for (const size_t size : {size_t{0}, size_t{1}, kMaxUdpPayloadLength}) {
                const UdpMessage message{.session_id = 0x12345678, .packet_id = 0x8765,
                    .target = target, .payload = std::span(payload).first(size)};
                const auto encoded = EncodeUdp(version, message);
                ASSERT_TRUE(encoded);
                EXPECT_EQ(encoded->wire.size(), encoded->header_size + size);
                const auto parsed = ParseUdpMessage(version, encoded->wire);
                ASSERT_TRUE(parsed);
                EXPECT_EQ(parsed->session_id, message.session_id);
                EXPECT_EQ(parsed->packet_id, message.packet_id);
                EXPECT_TRUE(parsed->target.SameEndpoint(target));
                EXPECT_TRUE(std::ranges::equal(parsed->payload, message.payload));
            }
        }
    }
}

TEST_F(HysteriaProtocol, HandshakeResponsesKeepTheirWireEncoding) {
    using namespace ::transport;
    const std::array<uint8_t, 21> expected_hello{
        1, 1, 2, 3, 4, 5, 6, 7, 8, 8, 7, 6, 5, 4, 3, 2, 1, 0, 2, 'o', 'k'};
    std::array<uint8_t, 32> hello{};
    const size_t hello_size = EncodeV1ServerHelloTo(
        hello, true, 0x0102030405060708ULL, 0x0807060504030201ULL, "ok");
    ASSERT_EQ(hello_size, expected_hello.size());
    EXPECT_TRUE(std::ranges::equal(std::span(hello).first(hello_size), expected_hello));

    const std::array<uint8_t, 9> expected_response{
        0, 0x12, 0x34, 0x56, 0x78, 0, 2, 'n', 'o'};
    std::array<uint8_t, 16> response{};
    const size_t response_size = EncodeV1ResponseTo(response, false, 0x12345678, "no");
    ASSERT_EQ(response_size, expected_response.size());
    EXPECT_TRUE(std::ranges::equal(std::span(response).first(response_size), expected_response));
}

}  // namespace

