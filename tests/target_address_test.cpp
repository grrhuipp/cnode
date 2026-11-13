#include <gtest/gtest.h>
#include "common/target_address.hpp"
#include <array>
#include <format>

namespace {
class InvalidTargetHost : public testing::TestWithParam<std::string_view> {};
TEST_P(InvalidTargetHost, RejectsAndDiscardsUnroutableHostBytes) {
    const ::common::TargetAddress target(std::string(GetParam()), 443);
    EXPECT_FALSE(target.IsValid());
    EXPECT_TRUE(target.host.empty());
}
INSTANTIATE_TEST_SUITE_P(Inputs, InvalidTargetHost, testing::Values(
    std::string_view("bad.example\r\nforged-log"), std::string_view("bad..example"),
    std::string_view("127.0.0.1:9"), std::string_view("127.0.0.1\0ignored", 17),
    std::string_view("[::ffff:127.0.0.1]"), std::string_view("::1\0ignored", 11)));

class InvalidTargetEndpoint : public testing::TestWithParam<const char*> {};
TEST_P(InvalidTargetEndpoint, RejectsMalformedHostnameOrBracketSyntax) {
    EXPECT_FALSE(::common::TargetAddress::Parse(GetParam()));
}
INSTANTIATE_TEST_SUITE_P(Inputs, InvalidTargetEndpoint, testing::Values(
    "bad..example:443", "[example.com]:443", "[127.0.0.1]:443", "[::1]:443junk"));

struct NumericCase { ::net::ip::address address; std::string_view text; std::string_view endpoint; };
class NumericTarget : public testing::TestWithParam<NumericCase> {};
TEST_P(NumericTarget, FormatsCanonicalEndpointWithoutLosingScope) {
    const auto& item = GetParam();
    const ::common::AddressText text(item.address);
    EXPECT_EQ(text.View(), item.text);
    const ::common::TargetAddress target(item.address, 65535);
    std::array<char, 128> logged;
    const auto end = std::format_to(logged.begin(), "{}", target);
    EXPECT_EQ(std::string_view(logged.data(), end - logged.begin()), item.endpoint);
}
INSTANTIATE_TEST_SUITE_P(Addresses, NumericTarget, testing::Values(
    NumericCase{::net::ip::make_address("255.255.255.255"), "255.255.255.255", "255.255.255.255:65535"},
    NumericCase{::net::ip::make_address("::"), "::", "[::]:65535"},
    NumericCase{::net::ip::make_address("2001:db8::1"), "2001:db8::1", "[2001:db8::1]:65535"},
    NumericCase{::net::ip::make_address("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
        "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535"},
    NumericCase{::net::ip::make_address("::ffff:192.0.2.1"), "::ffff:192.0.2.1", "192.0.2.1:65535"},
    NumericCase{::net::ip::address_v6(::net::ip::make_address_v6("fe80::1").to_bytes(), 0xffffffffUL),
        "fe80::1%4294967295", "[fe80::1%4294967295]:65535"},
    NumericCase{::net::ip::address_v6(::net::ip::make_address_v6("ff02::1").to_bytes(), 0xffffffffUL),
        "ff02::1%4294967295", "[ff02::1%4294967295]:65535"}));
}  // namespace

TEST(TargetAddress, CanonicalDomainIdentityIncludesPort) {
    const ::common::TargetAddress domain("example.com.", 443);
    ASSERT_TRUE(domain.IsValid());
    EXPECT_TRUE(domain.IsDomain());
    EXPECT_EQ(domain.host, "example.com");
    EXPECT_TRUE(domain.SameEndpoint(::common::TargetAddress("example.com", 443)));
    EXPECT_FALSE(domain.SameEndpoint(::common::TargetAddress("example.com", 8443)));
}

TEST(TargetAddress, ParsesBracketedIpv6Endpoint) {
    const auto ipv6 = ::common::TargetAddress::Parse("[2001:db8::1]:443");
    ASSERT_TRUE(ipv6);
    EXPECT_TRUE(ipv6->IsValid());
    EXPECT_TRUE(ipv6->IsIPv6());
}

TEST(TargetAddress, MappedIpv6SharesIpv4EndpointIdentity) {
    const ::common::TargetAddress mapped("::ffff:192.0.2.1", 443);
    ASSERT_TRUE(mapped.IsValid());
    EXPECT_TRUE(mapped.IsIPv4());
    ASSERT_TRUE(mapped.resolved_addr);
    EXPECT_EQ(mapped.resolved_addr->to_string(), "192.0.2.1");
    EXPECT_TRUE(mapped.SameEndpoint(::common::TargetAddress("192.0.2.1", 443)));
}

TEST(TargetAddress, FormatsNamedScopeUsingPlatformInterfaceName) {
    const ::net::ip::address_v6 address(::net::ip::make_address_v6("fe80::1").to_bytes(), 1);
    const ::common::AddressText text(address);
    EXPECT_EQ(text.View(), address.to_string());
}
