#include <gtest/gtest.h>

#include "common/ip_utils.hpp"

#include <array>
#include <string>
#include <string_view>

using iputil::ParseLiteral;
using namespace std::string_view_literals;

TEST(IpAddress, AcceptsCompleteIPv4IPv6AndNumericScopes) {
    const std::array valid{
        "0.0.0.0"sv, "255.255.255.255"sv, "192.0.2.1"sv, "127.0.0.1"sv,
        "::"sv, "::1"sv, "2001:DB8:0:1::ABCD"sv,
        "1:2:3:4:5:6:7:8"sv, "::ffff:192.0.2.1"sv,
        "1:2:3:4:5:6:192.0.2.1"sv, "fe80::1%1"sv, "fe80::1%4294967295"sv,
    };
    for (const auto text : valid) EXPECT_TRUE(ParseLiteral(text)) << text;
}

TEST(IpAddress, RejectsMalformedLiteralsAndEndpointSyntax) {
    const std::array invalid{
        ""sv, "example.com"sv, "192.0.2"sv, "192.0.2.999"sv, "192.00.2.1"sv,
        "192.0.2.1."sv, ".192.0.2.1"sv, "192..2.1"sv, "+192.0.2.1"sv,
        "0x7f000001"sv, "2130706433"sv, "127.1"sv, "127.0.0.1:9"sv,
        "[127.0.0.1]"sv, "[::1]"sv, "[::1]:443"sv, "::1:65536"sv,
        "127.0.0.1\0ignored"sv, "::1\0ignored"sv, "127.0.0.1 "sv, " ::1"sv,
        "127.0.0.1\r\n"sv, ":::"sv, "1::2::3"sv, "1:2:3:4:5:6:7"sv,
        "1:2:3:4:5:6:7:8:9"sv, "12345::1"sv, "::ffff:192.00.2.1"sv,
        "::ffff:192.0.2.256"sv, "1:2:3:4:5:192.0.2.1"sv,
        "fe80::1%"sv, "fe80::1%eth0"sv, "fe80::1%-1"sv, "fe80::1%+1"sv,
        "fe80::1%4294967296"sv, "fe80::1%1%2"sv, "127.0.0.1%1"sv,
        "fe80::1%1\0ignored"sv, "fe80::1%1:9"sv,
    };
    for (const auto text : invalid) EXPECT_FALSE(ParseLiteral(text)) << text;
}

TEST(IpAddress, ParsedViewsOwnTheirResultAndPreserveNumericScope) {
    // The parser must consume the view's length, without depending on a NUL
    // terminator or retaining the source buffer.
    std::string backing = "192.0.2.1:443";
    const auto prefix = ParseLiteral(std::string_view(backing).substr(0, 9));
    backing.assign(backing.size(), 'x');
    ASSERT_TRUE(prefix);
    EXPECT_EQ(prefix->to_v4().to_bytes(), (net::ip::address_v4::bytes_type{192, 0, 2, 1}));
    const auto scoped = ParseLiteral("fe80::1%4294967295");
    ASSERT_TRUE(scoped);
    EXPECT_EQ(scoped->to_v6().scope_id(), 4294967295ULL);
    const auto mapped = ParseLiteral("::ffff:192.0.2.1");
    ASSERT_TRUE(mapped);
    EXPECT_TRUE(mapped->is_v6());
    EXPECT_TRUE(mapped->to_v6().is_v4_mapped());
}

TEST(IpAddress, RoundTripsAllOctetsAndIPv6CompressionPositions) {

    // Independent byte -> OS/Asio formatter -> parser round trips exercise all
    // octet values and IPv6 compression positions without another text parser.
    for (unsigned int value = 0; value < 256; ++value) {
        ::net::ip::address_v4::bytes_type v4{};
        for (size_t i = 0; i < v4.size(); ++i) v4[i] = static_cast<unsigned char>(value + i * 67);
        const ::net::ip::address a4 = ::net::ip::address_v4(v4);
        ASSERT_FALSE((ParseLiteral(a4.to_string()) != a4));
        for (size_t zero = 0; zero < 16; zero += 2) {
            ::net::ip::address_v6::bytes_type v6{};
            for (size_t i = 0; i < v6.size(); ++i)
                if (i < zero || i >= zero + 6) v6[i] = static_cast<unsigned char>(value + i * 31);
            const ::net::ip::address a6 = ::net::ip::address_v6(v6);
            ASSERT_FALSE((ParseLiteral(a6.to_string()) != a6));
        }
    }
}

TEST(IpAddress, NetworkMasksHostBitsInItsOriginalFamily) {
    const auto ipv4 = iputil::ParseNetwork("192.0.2.129/24");
    ASSERT_TRUE(ipv4);
    EXPECT_EQ(ipv4->address, net::ip::make_address("192.0.2.0"));
    EXPECT_EQ(ipv4->prefix_length, 24);
    const auto ipv6 = iputil::ParseNetwork("2001:db8:abcd:1234::1/48");
    ASSERT_TRUE(ipv6);
    EXPECT_EQ(ipv6->address, net::ip::make_address("2001:db8:abcd::"));
    EXPECT_EQ(ipv6->prefix_length, 48);
    const auto mapped = iputil::ParseNetwork("::ffff:192.0.2.1");
    ASSERT_TRUE(mapped);
    EXPECT_EQ(mapped->address, net::ip::make_address("192.0.2.1"));
    EXPECT_EQ(mapped->prefix_length, 32);
}

TEST(IpAddress, NetworkRejectsAmbiguousAndOutOfRangePrefixes) {
    for (const auto text : {"192.0.2.1/024", "192.0.2.1/33", "::1/129", "::1/-1", "::1/64/1",
                            "::ffff:192.0.2.1/120", "192.0.2.1/"}) {
        EXPECT_FALSE(iputil::ParseNetwork(text)) << text;
    }
}
