#include <gtest/gtest.h>

#include "transport/internet/proxy_protocol.hpp"

#include <algorithm>
#include <array>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>

namespace {
::transport::internet::ProxyProtocolResult Parse(std::span<const uint8_t> bytes) {
    return ::transport::internet::ParseProxyProtocolHeader(bytes);
}
::transport::internet::ProxyProtocolResult Parse(std::string_view text) {
    return Parse(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(text.data()), text.size()));
}

std::array<uint8_t, 28> V2Header(uint8_t version_command, uint8_t family_transport) {
    std::array<uint8_t, 28> header{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51,
                                 0x55, 0x49, 0x54, 0x0A, version_command,
                                 family_transport, 0x00, 0x0C};
    constexpr std::array<uint8_t, 12> address{192, 0, 2, 1, 198, 51, 100, 1, 0x7D, 0x64, 0x01, 0xBB};
    std::copy(address.begin(), address.end(), header.begin() + 16);
    return header;
}

using namespace std::string_view_literals;
struct SourceCase {
    std::string_view family, host;
    bool accepted;
    std::string_view normalized_host{};
};
class ProxySourceLiteral : public testing::TestWithParam<SourceCase> {};
TEST_P(ProxySourceLiteral, RequiresBareLiteralOfDeclaredAddressFamily) {
    const auto& item = GetParam();
    const std::string packet = "PROXY " + std::string(item.family) + " " + std::string(item.host) +
        (item.family == "TCP4" ? " 198.51.100.1" : " 2001:db8::2") + " 32100 443\r\n";
    const auto result = Parse(std::string_view(packet));
    ASSERT_EQ(result.success(), item.accepted);
    if (item.accepted) {
        ASSERT_TRUE(result.src_addr.has_value());
        EXPECT_EQ(*result.src_addr, ::net::ip::make_address(std::string(item.normalized_host)));
        EXPECT_EQ(result.src_port, 32100);
        EXPECT_EQ(result.consumed, packet.size());
    }
}
INSTANTIATE_TEST_SUITE_P(V1, ProxySourceLiteral, testing::Values(
    SourceCase{"TCP4", "192.0.2.1", true, "192.0.2.1"},
    SourceCase{"TCP6", "2001:db8::1", true, "2001:db8::1"},
    // Family validation applies to the wire literal before source normalization.
    SourceCase{"TCP6", "::ffff:192.0.2.1", true, "192.0.2.1"},
    SourceCase{"TCP4", "::ffff:192.0.2.1", false},
    SourceCase{"TCP4", "192.0.2.1:9", false},
    SourceCase{"TCP4", "192.0.2.1\0ignored"sv, false}, SourceCase{"TCP6", "[2001:db8::1]", false},
    SourceCase{"TCP6", "2001:db8::1\0ignored"sv, false}, SourceCase{"TCP4", "192.00.2.1", false},
    SourceCase{"TCP4", "::1", false}, SourceCase{"TCP6", "192.0.2.1", false}));

class ProxyRoundTrip : public testing::TestWithParam<std::tuple<uint8_t, const char*>> {};
TEST_P(ProxyRoundTrip, EncodingPreservesSourceEndpointAndHeaderBoundary) {
    const auto [version, text] = GetParam();
    const auto address = ::net::ip::make_address(text);
    const ::tcp::endpoint source(address, 45678), destination(address, 443);
    std::array<uint8_t, ::transport::internet::kProxyProtocolMaxHeaderSize> encoded{};
    const auto size = ::transport::internet::EncodeProxyProtocolHeader(version, source, destination, encoded);
    ASSERT_NE(size, 0);
    const auto parsed = Parse(std::span<const uint8_t>(encoded.data(), size));
    ASSERT_TRUE(parsed.success());
    ASSERT_TRUE(parsed.src_addr.has_value());
    EXPECT_EQ(*parsed.src_addr, address);
    EXPECT_EQ(parsed.src_port, 45678);
    EXPECT_EQ(parsed.consumed, size);
}
INSTANTIATE_TEST_SUITE_P(VersionsAndFamilies, ProxyRoundTrip, testing::Combine(
    testing::Values(uint8_t{1}, uint8_t{2}), testing::Values("192.0.2.10", "2001:db8::10")));

class ProxyUnknown : public testing::TestWithParam<const char*> {};
TEST_P(ProxyUnknown, UnknownLineIgnoresAddressFieldsAndPreservesPayload) {
    const std::string line(GetParam());
    const auto parsed = Parse(std::string_view(line + "payload"));
    ASSERT_TRUE(parsed.success());
    EXPECT_FALSE(parsed.src_addr);
    EXPECT_EQ(parsed.consumed, line.size());
}
INSTANTIATE_TEST_SUITE_P(V1, ProxyUnknown, testing::Values(
    "PROXY UNKNOWN\r\n", "PROXY UNKNOWN ffff::1 ffff::2 1 2\r\n"));

TEST(ProxyProtocolLiteral, V1RejectsLineWithoutCrLfWithin107Bytes) {
    const std::string line = "PROXY " + std::string(101, 'x');
    EXPECT_TRUE(Parse(std::string_view(line).substr(0, 106)).incomplete());
    EXPECT_EQ(Parse(std::string_view(line)).status, ::transport::internet::ProxyProtocolParseStatus::Invalid);
    EXPECT_EQ(Parse(std::string_view(line + "\r\n")).status, ::transport::internet::ProxyProtocolParseStatus::Invalid);
}

class ProxyInvalidV1 : public testing::TestWithParam<const char*> {};
TEST_P(ProxyInvalidV1, RejectsInvalidDestinationPortOrTrailingFields) {
    EXPECT_EQ(Parse(std::string_view(GetParam())).status, ::transport::internet::ProxyProtocolParseStatus::Invalid);
}
INSTANTIATE_TEST_SUITE_P(V1, ProxyInvalidV1, testing::Values(
    "PROXY TCP4 192.0.2.1 GARBAGE 32100 443\r\n",
    "PROXY TCP4 192.0.2.1 198.51.100.1 32100 70000\r\n",
    "PROXY TCP4 192.0.2.1 198.51.100.1 32100 443 EXTRA\r\n"));

class ProxyInvalidV2 : public testing::TestWithParam<std::pair<uint8_t, uint8_t>> {};
TEST_P(ProxyInvalidV2, RejectsInvalidVersionCommandFamilyOrTransportBeforeAddressBlock) {
    const auto header = V2Header(GetParam().first, GetParam().second);
    EXPECT_EQ(Parse(header).status, ::transport::internet::ProxyProtocolParseStatus::Invalid);
    EXPECT_EQ(Parse(std::span(header).first(16)).status, ::transport::internet::ProxyProtocolParseStatus::Invalid);
}
INSTANTIATE_TEST_SUITE_P(V2, ProxyInvalidV2, testing::Values(
    std::pair<uint8_t, uint8_t>{0x11, 0x11}, std::pair<uint8_t, uint8_t>{0x31, 0x11},
    std::pair<uint8_t, uint8_t>{0x22, 0x11}, std::pair<uint8_t, uint8_t>{0x2f, 0x11},
    std::pair<uint8_t, uint8_t>{0x21, 0x41}, std::pair<uint8_t, uint8_t>{0x21, 0xf1},
    std::pair<uint8_t, uint8_t>{0x21, 0x13}, std::pair<uint8_t, uint8_t>{0x21, 0x1f}));

TEST(ProxyProtocolLiteral, V2RejectsOversizedLengthFromFixedHeader) {
    auto header = V2Header(0x21, 0x11);
    header[14] = 0x10;
    header[15] = 0;
    EXPECT_EQ(Parse(std::span(header).first(16)).status, ::transport::internet::ProxyProtocolParseStatus::Invalid);
}

class ProxyLocal : public testing::TestWithParam<uint8_t> {};
TEST_P(ProxyLocal, LocalCommandIgnoresFamilyButConsumesWholeDeclaredBlock) {
    const auto header = V2Header(0x20, GetParam());
    const auto parsed = Parse(header);
    ASSERT_TRUE(parsed.success());
    EXPECT_FALSE(parsed.src_addr);
    EXPECT_EQ(parsed.consumed, header.size());
    EXPECT_TRUE(Parse(std::span(header).first(16)).incomplete());
}
INSTANTIATE_TEST_SUITE_P(V2Families, ProxyLocal,
                        testing::Values(uint8_t{0x11}, uint8_t{0x41}, uint8_t{0x13}, uint8_t{0xff}));

TEST(ProxyProtocolLiteral, V2ParsesIndependentInetWireFixture) {
    const auto parsed = Parse(V2Header(0x21, 0x11));
    ASSERT_TRUE(parsed.success());
    ASSERT_TRUE(parsed.src_addr.has_value());
    EXPECT_EQ(*parsed.src_addr, ::net::ip::make_address("192.0.2.1"));
    EXPECT_EQ(parsed.src_port, 32100);
    EXPECT_EQ(parsed.consumed, 28);
}
}  // namespace
