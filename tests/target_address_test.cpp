#include <gtest/gtest.h>

#include "common/target_address.hpp"

#include <array>
#include <format>
#include <cstdio>

namespace {

bool Require(bool condition, const char* message) {
    if (!condition) std::fprintf(stderr, "%s\n", message);
    return condition;
}

}  // namespace

TEST(TargetAddress, Contract) {
    const ::TargetAddress empty;
    ASSERT_FALSE((!Require(!empty.IsValid() && !empty.IsIP() && !empty.IsDomain(),
                 "a default target must have an explicit invalid type")));

    const ::TargetAddress injected("bad.example\r\nforged-log", 443);
    ASSERT_FALSE((!Require(!injected.IsValid() && injected.host.empty(),
                 "an invalid target must not retain log-injectable bytes")));

    const ::TargetAddress empty_label("bad..example", 443);
    ASSERT_FALSE((!Require(!empty_label.IsValid(),
                 "a malformed DNS hostname must not become a valid target")));

    ASSERT_FALSE((!Require(!::TargetAddress::Parse("bad..example:443"),
                 "TargetAddress::Parse must reject malformed hostnames")));

    const ::TargetAddress domain("example.com.", 443);
    ASSERT_FALSE((!Require(domain.IsValid() && domain.IsDomain() &&
                     domain.host == "example.com",
                 "an absolute DNS hostname must be stored canonically")));

    const auto ipv6 = ::TargetAddress::Parse("[2001:db8::1]:443");
    ASSERT_FALSE((!Require(ipv6 && ipv6->IsValid() && ipv6->IsIPv6(),
                 "a bracketed IPv6 endpoint must remain valid")));

    const ::TargetAddress mapped("::ffff:192.0.2.1", 443);
    ASSERT_FALSE((!Require(mapped.IsValid() && mapped.IsIPv4() &&
                     mapped.resolved_addr->to_string() == "192.0.2.1",
                 "an IPv4-mapped IPv6 target must be canonicalized")));

    const ::TargetAddress same_domain("example.com", 443);
    const ::TargetAddress different_port("example.com", 8443);
    ASSERT_FALSE((!Require(domain.SameEndpoint(same_domain) &&
                     !domain.SameEndpoint(different_port),
                 "endpoint identity must use canonical host and port")));

    const ::TargetAddress same_mapped("192.0.2.1", 443);
    ASSERT_FALSE((!Require(mapped.SameEndpoint(same_mapped),
                 "canonical IP endpoints must compare equal")));
    using namespace std::string_view_literals;
    for (const auto text : {"127.0.0.1:9"sv, "127.0.0.1\0ignored"sv,
                            "[::ffff:127.0.0.1]"sv, "::1\0ignored"sv}) {
        const ::TargetAddress target(std::string(text), 443);
        ASSERT_FALSE((!Require(!target.IsValid() && target.host.empty(),
                     "invalid host bytes must never acquire a routable target")));
    }
    for (const auto text : {"[example.com]:443", "[127.0.0.1]:443", "[::1]:443junk"}) {
        ASSERT_FALSE((!Require(!::TargetAddress::Parse(text),
                     "endpoint brackets must contain exactly an IPv6 literal")));
    }
    struct NumericCase {
        ::net::ip::address address;
        std::string_view text;
        std::string_view endpoint;
    };
    const NumericCase numeric_cases[] = {
        {::net::ip::make_address("255.255.255.255"), "255.255.255.255", "255.255.255.255:65535"},
        {::net::ip::make_address("::"), "::", "[::]:65535"},
        {::net::ip::make_address("2001:db8::1"), "2001:db8::1", "[2001:db8::1]:65535"},
        {::net::ip::make_address("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
         "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535"},
        {::net::ip::make_address("::ffff:192.0.2.1"), "::ffff:192.0.2.1", "192.0.2.1:65535"},
        {::net::ip::address_v6(::net::ip::make_address_v6("fe80::1").to_bytes(), 0xffffffffUL),
         "fe80::1%4294967295", "[fe80::1%4294967295]:65535"},
        {::net::ip::address_v6(::net::ip::make_address_v6("ff02::1").to_bytes(), 0xffffffffUL),
         "ff02::1%4294967295", "[ff02::1%4294967295]:65535"},
    };
    for (const auto& test : numeric_cases) {
        const ::iputil::AddressText text(test.address);
        ASSERT_FALSE((!Require(text.View() == test.text, "numeric IP text or scope changed")));
        const ::TargetAddress target(test.address, 65535);
        std::array<char, 128> logged;
        const auto end = std::format_to(logged.begin(), "{}", target);
        ASSERT_FALSE((!Require(std::string_view(logged.data(), end - logged.begin()) == test.endpoint,
                     "logging must preserve normalized endpoint text")));
    }
    const ::net::ip::address_v6 named_scope(
        ::net::ip::make_address_v6("fe80::1").to_bytes(), 1);
    const ::iputil::AddressText scoped_text(named_scope);
    ASSERT_FALSE((!Require(scoped_text.View() == named_scope.to_string(),
                 "interface-name scope formatting must match the platform")));
}
