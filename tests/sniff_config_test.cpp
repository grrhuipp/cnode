#include <gtest/gtest.h>

#include "proxy/sniff_config.hpp"

#include <cstdio>

namespace {

bool Require(bool condition, const char* message) {
    if (!condition) std::fprintf(stderr, "%s\n", message);
    return condition;
}

}  // namespace

TEST(SniffConfig, Contract) {
    ::SniffConfig config;
    config.domains_excluded = {"Blocked.Example", "safe.example"};

    ASSERT_FALSE((!Require(config.IsDomainExcluded("blocked.example"),
                 "domain exclusions must be ASCII case-insensitive")));
    ASSERT_FALSE((!Require(config.IsDomainExcluded("SAFE.EXAMPLE"),
                 "uppercase sniffed domains must remain excluded")));
    ASSERT_FALSE((!Require(!config.IsDomainExcluded("not-safe.example"),
                 "domain exclusions must remain exact names")));
    ASSERT_FALSE((!Require(config.IsDomainExcluded("blocked.example."),
                 "an absolute DNS name must not bypass domain exclusions")));
    ASSERT_FALSE((!Require(config.MatchesDestOverride("tls") && config.MatchesDestOverride("http") &&
                 config.MatchesDestOverride("quic") && !config.MatchesDestOverride("bittorrent"),
                 "default destOverride must be tls, http and quic")));
    config.dest_override = ::SniffConfig::DestOverrideBit("quic");
    ASSERT_FALSE((!Require(config.MatchesDestOverride("quic"),
                 "quic destOverride must be recognized")));
    ASSERT_FALSE((!Require(!config.MatchesDestOverride("tls"),
                 "unlisted destOverride protocols must not match")));
    ASSERT_FALSE((!Require(::SniffConfig::DestOverrideBit("fakedns") == 0 &&
                 !config.MatchesDestOverride("fakedns"),
                 "unsupported protocol names must not map to a destOverride bit")));
}
