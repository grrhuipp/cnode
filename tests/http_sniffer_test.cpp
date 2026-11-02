#include "acppnode/sniff/sniffer.hpp"

#include <cstdio>
#include <span>
#include <string_view>

namespace {

acpp::SniffResult SniffHttp(std::string_view request) {
    acpp::HttpSniffer sniffer;
    return sniffer.Sniff(std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(request.data()), request.size()));
}

bool Require(bool condition, const char* message) {
    if (!condition) std::fprintf(stderr, "%s\n", message);
    return condition;
}

}  // namespace

int main() {
    const auto valid = SniffHttp(
        "GET / HTTP/1.1\r\nHost: example.com:443\r\nUser-Agent: test\r\n\r\n");
    if (!Require(valid.success && valid.domain == "example.com" &&
                     valid.port == 443,
                 "a canonical HTTP request must be sniffed")) return 1;

    if (!Require(!SniffHttp(
            "GET /Host:evil HTTP/1.1\r\nUser-Agent: test\r\n\r\n").success,
        "Host text in the request target must not be treated as a header")) {
        return 2;
    }
    if (!Require(!SniffHttp(
            "GET / HTTP/1.1\r\nX-Host: evil.example\r\n\r\n").success,
        "Host text inside another header name must not match")) return 3;
    if (!Require(!SniffHttp(
            "GET / HTTP/1.1\r\nHost: example.com:99999\r\n\r\n").success,
        "an out-of-range Host port must be rejected")) return 4;
    if (!Require(!SniffHttp(
            "GET / HTTP/1.1\r\nHost: first.example\r\nHost: second.example\r\n\r\n").success,
        "duplicate Host headers must be rejected")) return 5;
    if (!Require(!SniffHttp(
            "GET / HTTP/1.1\r\nHost: example.com").success,
        "an incomplete HTTP header block must be rejected")) return 6;
    if (!Require(!SniffHttp(
            "GET / HTTP/1.1\nHost: example.com\n\n").success,
        "LF-only HTTP headers must be rejected")) return 7;
    if (!Require(!SniffHttp(
            "GET / HTTP/1.1\r\nHost: bad host\r\n\r\n").success,
        "an invalid HTTP authority must be rejected")) return 8;

    if (!Require(!SniffHttp(
            "GET / HTTP/1.1\r\nHost: [not:ipv6]:443\r\n\r\n").success,
        "a bracketed non-IPv6 host must be rejected")) return 9;
    if (!Require(!SniffHttp(
            "GET / HTTP/1.1\r\nHost: bad..example\r\n\r\n").success,
        "an empty DNS label must be rejected")) return 10;
    if (!Require(!SniffHttp(
            "GET / HTTP/1.1\r\nHost: -bad.example\r\n\r\n").success,
        "a DNS label must not start with a hyphen")) return 11;

    const auto ipv6 = SniffHttp(
        "CONNECT [2001:db8::1]:8443 HTTP/1.1\r\n"
        "hOsT:\t[2001:db8::1]:8443\t\r\n\r\n");
    if (!Require(ipv6.success && ipv6.domain == "2001:db8::1" &&
                     ipv6.port == 8443,
                 "a bracketed IPv6 authority must be parsed")) return 12;

    const auto absolute_dns = SniffHttp(
        "GET / HTTP/1.1\r\nHost: example.com.\r\n\r\n");
    if (!Require(absolute_dns.success && absolute_dns.domain == "example.com.",
                 "an absolute DNS hostname must remain valid for HTTP")) return 13;
    return 0;
}
