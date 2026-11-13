#include <gtest/gtest.h>
#include "routing/dispatcher.hpp"
namespace {
class ExcludedDomain : public testing::TestWithParam<const char*> {};
TEST_P(ExcludedDomain, MatchesCaseInsensitivelyAndIgnoresRootDot) {
    ::routing::SniffConfig config;
    config.domains_excluded = {"Blocked.Example", "safe.example"};
    EXPECT_TRUE(config.IsDomainExcluded(GetParam()));
    EXPECT_FALSE(config.IsDomainExcluded("not-safe.example"));
}
INSTANTIATE_TEST_SUITE_P(Names, ExcludedDomain,
    testing::Values("blocked.example", "SAFE.EXAMPLE", "blocked.example."));
}

TEST(SniffConfig, OverridesOnlySupportedSelectedProtocols) {
    ::routing::SniffConfig config;
    config.dest_override = ::routing::SniffedProtocolBit("quic");
    EXPECT_TRUE(config.MatchesDestOverride("quic"));
    EXPECT_FALSE(config.MatchesDestOverride("tls"));
    EXPECT_EQ(::routing::SniffedProtocolBit("fakedns"), 0);
    EXPECT_FALSE(config.MatchesDestOverride("fakedns"));
}
