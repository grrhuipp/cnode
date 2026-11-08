#include <gtest/gtest.h>

#include "sniff/sniffer.hpp"

#include <cstdio>
#include <span>
#include <string_view>

namespace {

::SniffResult SniffHttp(std::string_view request) {
    return ::SniffHttp(std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(request.data()), request.size()));
}

bool Require(bool condition, const char* message) {
    if (!condition) std::fprintf(stderr, "%s\n", message);
    return condition;
}

}  // namespace

TEST(HttpSniffer, Contract) {
    const auto valid = SniffHttp(
        "GET / HTTP/1.1\r\nHost: example.com:443\r\nUser-Agent: test\r\n\r\n");
    ASSERT_FALSE((!Require(valid.success && valid.domain == "example.com" &&
                     valid.port == 443,
                 "a canonical HTTP request must be sniffed")));

    ASSERT_FALSE((!Require(!SniffHttp(
            "GET /Host:evil HTTP/1.1\r\nUser-Agent: test\r\n\r\n").success,
        "Host text in the request target must not be treated as a header")));
    ASSERT_FALSE((!Require(!SniffHttp(
            "GET / HTTP/1.1\r\nX-Host: evil.example\r\n\r\n").success,
        "Host text inside another header name must not match")));
    ASSERT_FALSE((!Require(!SniffHttp(
            "GET / HTTP/1.1\r\nHost: example.com:99999\r\n\r\n").success,
        "an out-of-range Host port must be rejected")));
    ASSERT_FALSE((!Require(!SniffHttp(
            "GET / HTTP/1.1\r\nHost: first.example\r\nHost: second.example\r\n\r\n").success,
        "duplicate Host headers must be rejected")));
    const auto partial_http = SniffHttp("GET / HTTP/1.1\r\nHost: example.com");
    ASSERT_FALSE((!Require(!partial_http.success && partial_http.need_more &&
                     partial_http.protocol == "http",
        "an incomplete HTTP header block must request more bytes")));
    ASSERT_FALSE((!Require(!SniffHttp(
            "GET / HTTP/1.1\nHost: example.com\n\n").success,
        "LF-only HTTP headers must be rejected")));
    ASSERT_FALSE((!Require(!SniffHttp(
            "GET / HTTP/1.1\r\nHost: bad host\r\n\r\n").success,
        "an invalid HTTP authority must be rejected")));

    ASSERT_FALSE((!Require(!SniffHttp(
            "GET / HTTP/1.1\r\nHost: [not:ipv6]:443\r\n\r\n").success,
        "a bracketed non-IPv6 host must be rejected")));
    ASSERT_FALSE((!Require(!SniffHttp(
            "GET / HTTP/1.1\r\nHost: bad..example\r\n\r\n").success,
        "an empty DNS label must be rejected")));
    ASSERT_FALSE((!Require(!SniffHttp(
            "GET / HTTP/1.1\r\nHost: -bad.example\r\n\r\n").success,
        "a DNS label must not start with a hyphen")));

    const auto ipv6 = SniffHttp(
        "CONNECT [2001:db8::1]:8443 HTTP/1.1\r\n"
        "hOsT:\t[2001:db8::1]:8443\t\r\n\r\n");
    ASSERT_FALSE((!Require(ipv6.success && ipv6.domain == "2001:db8::1" &&
                     ipv6.port == 8443,
                 "a bracketed IPv6 authority must be parsed")));

    const auto absolute_dns = SniffHttp(
        "GET / HTTP/1.1\r\nHost: example.com.\r\n\r\n");
    ASSERT_FALSE((!Require(absolute_dns.success && absolute_dns.domain == "example.com.",
                 "an absolute DNS hostname must remain valid for HTTP")));
}
