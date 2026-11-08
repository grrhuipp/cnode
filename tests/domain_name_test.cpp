#include <gtest/gtest.h>

#include "common/domain_name.hpp"

#include <cstdio>
#include <string>

namespace {

bool Require(bool condition, const char* message) {
    if (!condition) std::fprintf(stderr, "%s\n", message);
    return condition;
}

}  // namespace

TEST(DomainName, Contract) {
    using ::domain::IsValidDnsHostname;
    using ::domain::DnsHostnamesEqual;
    using ::domain::NormalizeDnsHostnameInPlace;
    using ::domain::TrailingDotPolicy;

    ASSERT_FALSE((!Require(IsValidDnsHostname("example.com", TrailingDotPolicy::Forbid),
                 "a canonical DNS hostname must be valid")));
    ASSERT_FALSE((!Require(IsValidDnsHostname(
                     std::string(63, 'a') + ".example",
                     TrailingDotPolicy::Forbid),
                 "a 63-octet DNS label must be valid")));
    ASSERT_FALSE((!Require(!IsValidDnsHostname(
                     std::string(64, 'a') + ".example",
                     TrailingDotPolicy::Forbid),
                 "a DNS label longer than 63 octets must be rejected")));
    ASSERT_FALSE((!Require(IsValidDnsHostname(
                     "example.com.", TrailingDotPolicy::Allow),
                 "an allowed absolute DNS name must be valid")));
    ASSERT_FALSE((!Require(!IsValidDnsHostname(
                     "example.com.", TrailingDotPolicy::Forbid),
                 "a forbidden trailing dot must be rejected")));
    ASSERT_FALSE((!Require(!IsValidDnsHostname(
                     "bad-.example", TrailingDotPolicy::Forbid),
                 "a DNS label must not end with a hyphen")));
    ASSERT_FALSE((!Require(!IsValidDnsHostname(
                     "bad_name.example", TrailingDotPolicy::Forbid),
                 "non-hostname DNS label bytes must be rejected")));

    ASSERT_FALSE((!Require(DnsHostnamesEqual("Example.COM.", "example.com"),
                 "DNS hostname equality must ignore case and the root dot")));
    std::string canonical = "Example.COM.";
    NormalizeDnsHostnameInPlace(canonical);
    ASSERT_FALSE((!Require(canonical == "example.com",
                 "DNS hostname storage must use one canonical form")));
}
