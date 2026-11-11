#include <gtest/gtest.h>

#include "common/domain_name.hpp"

#include <string>

using domain::DnsHostnamesEqual;
using domain::IsValidDnsHostname;
using domain::NormalizeDnsHostnameInPlace;
using domain::TrailingDotPolicy;

TEST(DomainName, EnforcesLabelLengthAndHostCharacters) {
    EXPECT_TRUE(IsValidDnsHostname("example.com", TrailingDotPolicy::Forbid));
    EXPECT_TRUE(IsValidDnsHostname(std::string(63, 'a') + ".example", TrailingDotPolicy::Forbid));
    EXPECT_FALSE(IsValidDnsHostname(std::string(64, 'a') + ".example", TrailingDotPolicy::Forbid));
    EXPECT_FALSE(IsValidDnsHostname("bad-.example", TrailingDotPolicy::Forbid));
    EXPECT_FALSE(IsValidDnsHostname("bad_name.example", TrailingDotPolicy::Forbid));
}

TEST(DomainName, AppliesExplicitTrailingRootPolicy) {
    EXPECT_TRUE(IsValidDnsHostname("example.com.", TrailingDotPolicy::Allow));
    EXPECT_FALSE(IsValidDnsHostname("example.com.", TrailingDotPolicy::Forbid));
}

TEST(DomainName, ComparisonAndStorageNormalizeCaseAndRootDot) {
    EXPECT_TRUE(DnsHostnamesEqual("Example.COM.", "example.com"));
    std::string canonical = "Example.COM.";
    NormalizeDnsHostnameInPlace(canonical);
    EXPECT_EQ(canonical, "example.com");
}
