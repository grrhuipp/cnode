#include <gtest/gtest.h>

#include "common/ip_address.hpp"

#include <array>
#include <cstdio>
#include <string>
#include <string_view>

TEST(IpAddress, Contract) {
    using ::iputil::ParseLiteral;
    using namespace std::string_view_literals;
    const std::array valid{
        "0.0.0.0"sv, "255.255.255.255"sv, "192.0.2.1"sv, "127.0.0.1"sv,
        "::"sv, "::1"sv, "2001:DB8:0:1::ABCD"sv,
        "1:2:3:4:5:6:7:8"sv, "::ffff:192.0.2.1"sv,
        "1:2:3:4:5:6:192.0.2.1"sv, "fe80::1%1"sv, "fe80::1%4294967295"sv,
    };
    for (const auto text : valid) {
        if (!ParseLiteral(text)) {
            std::fprintf(stderr, "valid literal rejected: %.*s\n", static_cast<int>(text.size()), text.data());
            FAIL() << "valid literal rejected: %.*s";
        }
    }
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
    for (const auto text : invalid) {
        if (ParseLiteral(text)) {
            std::fprintf(stderr, "invalid literal accepted: %.*s\n", static_cast<int>(text.size()), text.data());
            FAIL() << "invalid literal accepted: " << text;
        }
    }
    // The parser must consume the view's length, without depending on a NUL
    // terminator or retaining the source buffer.
    std::string backing = "192.0.2.1:443";
    const auto prefix = ParseLiteral(std::string_view(backing).substr(0, 9));
    backing.assign(backing.size(), 'x');
    ASSERT_FALSE((!prefix || prefix->to_v4().to_bytes() != ::net::ip::address_v4::bytes_type{192, 0, 2, 1}));
    const auto scoped = ParseLiteral("fe80::1%4294967295");
    ASSERT_FALSE((!scoped || scoped->to_v6().scope_id() != 4294967295ULL));
    const auto mapped = ParseLiteral("::ffff:192.0.2.1");
    ASSERT_FALSE((!mapped || !mapped->is_v6() || !mapped->to_v6().is_v4_mapped()));

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
    std::printf("IP literals: %zu valid, %zu invalid, 2304 byte round trips passed\n", valid.size(), invalid.size());
}
