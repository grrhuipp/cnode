#include <gtest/gtest.h>

#include "infra/config_types.hpp"

#include <array>
#include <string_view>

TEST(RoutingIpNetwork, MasksIpv4HostBits) {
    const auto network = ::infra::RoutingIpNetwork::Parse("192.0.2.129/24");
    ASSERT_TRUE(network);
    EXPECT_FALSE(network->IsV6());
    EXPECT_EQ(network->Prefix(), 24);
    EXPECT_EQ(network->Network()[0], 192);
    EXPECT_EQ(network->Network()[1], 0);
    EXPECT_EQ(network->Network()[2], 2);
    EXPECT_EQ(network->Network()[3], 0);
}

TEST(RoutingIpNetwork, BareIpv4MatchesOneHost) {
    const auto network = ::infra::RoutingIpNetwork::Parse("198.51.100.7");
    ASSERT_TRUE(network);
    EXPECT_FALSE(network->IsV6());
    EXPECT_EQ(network->Prefix(), 32);
    EXPECT_EQ(network->Network()[3], 7);
}

TEST(RoutingIpNetwork, MasksIpv6HostBits) {
    const auto network = ::infra::RoutingIpNetwork::Parse("2001:db8:abcd:1234::1/48");
    ASSERT_TRUE(network);
    EXPECT_TRUE(network->IsV6());
    EXPECT_EQ(network->Prefix(), 48);
    const std::array<uint8_t, 6> prefix{0x20, 0x01, 0x0d, 0xb8, 0xab, 0xcd};
    for (size_t i = 0; i < prefix.size(); ++i) {
        EXPECT_EQ(network->Network()[i], prefix[i]) << i;
    }
    for (size_t i = prefix.size(); i < network->Network().size(); ++i) {
        EXPECT_EQ(network->Network()[i], 0) << i;
    }
}

TEST(RoutingIpNetwork, BareIpv6MatchesOneHost) {
    const auto network = ::infra::RoutingIpNetwork::Parse("2001:db8::1");
    ASSERT_TRUE(network);
    EXPECT_TRUE(network->IsV6());
    EXPECT_EQ(network->Prefix(), 128);
    EXPECT_EQ(network->Network()[15], 1);
}

namespace {
using namespace std::string_view_literals;
class InvalidIpNetwork : public ::testing::TestWithParam<std::string_view> {};
TEST_P(InvalidIpNetwork, RejectsMalformedAddressOrPrefix) {
    EXPECT_FALSE(::infra::RoutingIpNetwork::Parse(GetParam()));
}
INSTANTIATE_TEST_SUITE_P(ParseErrors, InvalidIpNetwork, ::testing::Values(
    ""sv, "not-an-ip"sv, "192.0.2.1/"sv, "192.0.2.1/24junk"sv,
    "192.0.2.1/-1"sv, "192.0.2.1/33"sv, "192.0.2.1/24/1"sv,
    "2001:db8::/"sv, "2001:db8::/32junk"sv, "2001:db8::/129"sv,
    "2001:db8::/64/1"sv, "192.0.2.1:9/24"sv, "192.0.2.1\0ignored/24"sv,
    "[2001:db8::1]/64"sv, "192.0.2.1 /24"sv,
    "192.00.2.1/24"sv, "fe80::1%invalid/64"sv));
}  // namespace
