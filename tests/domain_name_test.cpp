#include "acppnode/common/domain_name.hpp"

#include <cstdio>
#include <string>

namespace {

bool Require(bool condition, const char* message) {
    if (!condition) std::fprintf(stderr, "%s\n", message);
    return condition;
}

}  // namespace

int main() {
    using acpp::domain::IsIpv4AddressLiteral;
    using acpp::domain::IsValidDnsHostname;
    using acpp::domain::TrailingDotPolicy;

    if (!Require(IsValidDnsHostname("example.com", TrailingDotPolicy::Forbid),
                 "a canonical DNS hostname must be valid")) return 1;
    if (!Require(IsValidDnsHostname(
                     std::string(63, 'a') + ".example",
                     TrailingDotPolicy::Forbid),
                 "a 63-octet DNS label must be valid")) return 2;
    if (!Require(!IsValidDnsHostname(
                     std::string(64, 'a') + ".example",
                     TrailingDotPolicy::Forbid),
                 "a DNS label longer than 63 octets must be rejected")) return 3;
    if (!Require(IsValidDnsHostname(
                     "example.com.", TrailingDotPolicy::Allow),
                 "an allowed absolute DNS name must be valid")) return 4;
    if (!Require(!IsValidDnsHostname(
                     "example.com.", TrailingDotPolicy::Forbid),
                 "a forbidden trailing dot must be rejected")) return 5;
    if (!Require(!IsValidDnsHostname(
                     "bad-.example", TrailingDotPolicy::Forbid),
                 "a DNS label must not end with a hyphen")) return 6;
    if (!Require(!IsValidDnsHostname(
                     "bad_name.example", TrailingDotPolicy::Forbid),
                 "non-hostname DNS label bytes must be rejected")) return 7;

    if (!Require(IsIpv4AddressLiteral("192.0.2.1"),
                 "a canonical IPv4 literal must be recognized")) return 8;
    if (!Require(!IsIpv4AddressLiteral("192.0.2.999"),
                 "an out-of-range IPv4 octet must be rejected")) return 9;
    if (!Require(!IsIpv4AddressLiteral("192.0.2"),
                 "an incomplete IPv4 literal must be rejected")) return 10;
    if (!Require(!IsIpv4AddressLiteral("192.00.2.1"),
                 "a non-canonical leading zero must not become an IP literal")) return 11;
    return 0;
}
