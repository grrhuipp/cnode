#include <gtest/gtest.h>

#include "sniff/sniffer.hpp"

#include <span>
#include <string_view>

namespace {
::SniffResult SniffHttp(std::string_view request) {
    return ::SniffHttp(std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(request.data()), request.size()));
}

TEST(HttpSniffer, ExtractsHostAndExplicitPort) {
    const auto result = SniffHttp("GET / HTTP/1.1\r\nHost: example.com:443\r\nUser-Agent: test\r\n\r\n");
    ASSERT_TRUE(result.success);
    EXPECT_EQ(result.domain, "example.com");
    EXPECT_EQ(result.port, 443);
}

class HttpRejectedRequest : public testing::TestWithParam<const char*> {};
TEST_P(HttpRejectedRequest, RejectsMissingAmbiguousOrMalformedAuthority) {
    EXPECT_FALSE(SniffHttp(GetParam()).success);
}
INSTANTIATE_TEST_SUITE_P(Headers, HttpRejectedRequest, testing::Values(
    "GET /Host:evil HTTP/1.1\r\nUser-Agent: test\r\n\r\n",
    "GET / HTTP/1.1\r\nX-Host: evil.example\r\n\r\n",
    "GET / HTTP/1.1\r\nHost: example.com:99999\r\n\r\n",
    "GET / HTTP/1.1\r\nHost: first.example\r\nHost: second.example\r\n\r\n",
    "GET / HTTP/1.1\nHost: example.com\n\n",
    "GET / HTTP/1.1\r\nHost: bad host\r\n\r\n",
    "GET / HTTP/1.1\r\nHost: [not:ipv6]:443\r\n\r\n",
    "GET / HTTP/1.1\r\nHost: bad..example\r\n\r\n",
    "GET / HTTP/1.1\r\nHost: -bad.example\r\n\r\n"));

TEST(HttpSniffer, IncompleteHeadersRequestMoreBytes) {
    const auto result = SniffHttp("GET / HTTP/1.1\r\nHost: example.com");
    EXPECT_FALSE(result.success);
    EXPECT_TRUE(result.need_more);
    EXPECT_EQ(result.protocol, "http");
}

TEST(HttpSniffer, ParsesBracketedIpv6WithCaseInsensitiveHostHeader) {
    const auto result = SniffHttp("CONNECT [2001:db8::1]:8443 HTTP/1.1\r\nhOsT:\t[2001:db8::1]:8443\t\r\n\r\n");
    ASSERT_TRUE(result.success);
    EXPECT_EQ(result.domain, "2001:db8::1");
    EXPECT_EQ(result.port, 8443);
}

TEST(HttpSniffer, AcceptsAbsoluteDnsHostName) {
    const auto result = SniffHttp("GET / HTTP/1.1\r\nHost: example.com.\r\n\r\n");
    ASSERT_TRUE(result.success);
    EXPECT_EQ(result.domain, "example.com.");
}
}  // namespace
