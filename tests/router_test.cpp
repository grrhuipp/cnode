#include <gtest/gtest.h>

#include "app/router.hpp"
#include "common/session.hpp"
#include "infra/config_types.hpp"

#include <regex>
#include <stdexcept>

namespace {
using ::app::Router;

::infra::RoutingConfig RoutingRules() {
    ::infra::RoutingConfig config;
    config.domain_strategy = ::routing::DomainStrategy::IPIfNonMatch;
    ::infra::RouteRuleConfig domain;
    domain.domain_suffix = {"example.com"};
    domain.network = {"tcp"};
    domain.outbound_tag = "domain-proxy";
    ::infra::RouteRuleConfig network;
    network.ip = {*::infra::RoutingIpNetwork::Parse("192.0.2.0/24"),
                  *::infra::RoutingIpNetwork::Parse("2001:db8::/32")};
    network.outbound_tag = "ip-proxy";
    config.rules = {domain, network};
    return config;
}

TEST(Router, FirstMatchingRuleWins) {
    const Router router(RoutingRules(), nullptr);
    ::common::Context ctx;
    ctx.content.network = ::common::Network::TCP;
    ctx.outbound.target = ::common::TargetAddress("WWW.EXAMPLE.COM.", 443);
    ctx.outbound.target.resolved_addr = ::net::ip::make_address("192.0.2.1");
    const auto match = router.Route(ctx);
    EXPECT_TRUE(match.matched);
    EXPECT_EQ(match.outbound_tag, "domain-proxy");
}

TEST(Router, NetworkConstraintSkipsTcpRuleForUdp) {
    const Router router(RoutingRules(), nullptr);
    ::common::Context ctx;
    ctx.content.network = ::common::Network::UDP;
    ctx.outbound.target = ::common::TargetAddress("example.com", 443);
    ctx.outbound.target.resolved_addr = ::net::ip::make_address("192.0.2.1");
    const auto match = router.Route(ctx);
    EXPECT_TRUE(match.matched);
    EXPECT_EQ(match.outbound_tag, "ip-proxy");
}

TEST(Router, MatchesIpv6Network) {
    const Router router(RoutingRules(), nullptr);
    ::common::Context ctx;
    ctx.outbound.target = ::common::TargetAddress("2001:db8::7", 53);
    EXPECT_EQ(router.Route(ctx).outbound_tag, "ip-proxy");
}

TEST(Router, RouteOnlyTargetControlsPortAndResolvedIpMatching) {
    auto config = RoutingRules();
    ::infra::RouteRuleConfig port;
    port.port = {::infra::RoutingPortRange{8443, 8443}};
    port.outbound_tag = "port-proxy";
    config.rules[0] = port;
    const Router router(config, nullptr);
    ::common::Context ctx;
    ctx.outbound.target = ::common::TargetAddress("example.org", 80);
    ctx.outbound.route_target = ::common::TargetAddress("sniffed.example.org", 8443);
    EXPECT_EQ(router.Route(ctx).outbound_tag, "port-proxy");
    ctx.outbound.route_target = ::common::TargetAddress("sniffed.example.org", 443);
    ctx.outbound.route_target.resolved_addr = ::net::ip::make_address("192.0.2.99");
    EXPECT_EQ(router.Route(ctx).outbound_tag, "ip-proxy");
}

TEST(Router, SuffixBoundaryMissHasNoFallback) {
    const Router router(RoutingRules(), nullptr);
    ::common::Context ctx;
    ctx.content.network = ::common::Network::TCP;
    ctx.outbound.target = ::common::TargetAddress("notexample.com", 443);
    const auto match = router.Route(ctx);
    EXPECT_FALSE(match.matched);
    EXPECT_TRUE(match.outbound_tag.empty());
}

TEST(Router, ConfigurationReplacementPreservesExistingRulesAndDecisions) {
    auto config = RoutingRules();
    const Router router(config, nullptr);
    const ::routing::Router& query = router;
    ::common::Context ctx;
    ctx.content.network = ::common::Network::TCP;
    ctx.outbound.target = ::common::TargetAddress("example.com", 443);
    const auto decision = query.Route(ctx);
    config.rules[0].outbound_tag = "replacement";
    config.domain_strategy = ::routing::DomainStrategy::AsIs;
    const Router replacement(config, nullptr);
    config.rules.clear();
    EXPECT_EQ(query.Route(ctx).outbound_tag, "domain-proxy");
    EXPECT_EQ(decision.outbound_tag, "domain-proxy");
    EXPECT_EQ(replacement.Route(ctx).outbound_tag, "replacement");
    EXPECT_EQ(query.DomainStrategy(), ::routing::DomainStrategy::IPIfNonMatch);
}

TEST(Router, PrimaryAndAdditionalInboundTagsParticipateInRouting) {
    ::infra::RoutingConfig config;
    ::infra::RouteRuleConfig main_tag;
    main_tag.inbound_tag = {std::string(96, 'm')};
    main_tag.domain_full = {"main.example"};
    main_tag.outbound_tag = "main-out";
    ::infra::RouteRuleConfig extra_tag;
    extra_tag.inbound_tag = {std::string(112, 'x')};
    extra_tag.domain_full = {"extra.example"};
    extra_tag.outbound_tag = "extra-out";
    config.rules = {main_tag, extra_tag};
    const Router router(config, nullptr);
    ::common::Context ctx;
    ctx.inbound.tag = std::string(96, 'm');
    ctx.inbound.tags.emplace_back(std::string(112, 'x'));
    ctx.outbound.target = ::common::TargetAddress("main.example", 443);
    EXPECT_EQ(router.Route(ctx).outbound_tag, "main-out");
    ctx.outbound.target = ::common::TargetAddress("extra.example", 443);
    EXPECT_EQ(router.Route(ctx).outbound_tag, "extra-out");
    ctx.inbound.tags.clear();
    EXPECT_FALSE(router.Route(ctx).matched);
}

class InvalidRoutingRule : public ::testing::TestWithParam<int> {};
TEST_P(InvalidRoutingRule, RejectsInvalidConfiguration) {
    auto config = RoutingRules();
    auto invalid = config.rules.front();
    switch (GetParam()) {
    case 0: invalid.domain_regex = {"["}; break;
    case 1: invalid = {}; invalid.outbound_tag = "direct"; break;
    case 2: invalid.outbound_tag.clear(); break;
    case 3: invalid.geosite = {"cn"}; break;
    }
    config.rules.push_back(invalid);
    if (GetParam() == 0) {
        EXPECT_THROW((Router(config, nullptr)), std::regex_error);
    } else {
        EXPECT_THROW((Router(config, nullptr)), std::logic_error);
    }
}
INSTANTIATE_TEST_SUITE_P(ConfigurationErrors, InvalidRoutingRule,
    ::testing::Values(0, 1, 2, 3), ([](const ::testing::TestParamInfo<int>& info) {
        constexpr const char* names[]{"InvalidRegex", "UnconditionalRule", "EmptyOutbound", "UnresolvedGeo"};
        return names[info.param];
    }));

TEST(Router, EmptyRulesHaveNoImplicitDefault) {
    const Router router(::infra::RoutingConfig{}, nullptr);
    EXPECT_FALSE(router.Route(::common::Context{}).matched);
}
}  // namespace
