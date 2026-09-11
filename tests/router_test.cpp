#include "acppnode/app/router/router.hpp"
#include "acppnode/common/session.hpp"
#include "acppnode/infra/runtime_config_types.hpp"

#include <concepts>
#include <iostream>
#include <memory>
#include <regex>
#include <stdexcept>

namespace {

using acpp::app::router::Router;
static_assert(std::derived_from<Router, acpp::routing::Router>);
static_assert(!std::default_initializable<Router>);
static_assert(!std::movable<Router>);

void Require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

template <typename Exception, typename Function>
void RequireThrows(Function&& function, const char* message) {
    try {
        function();
    } catch (const Exception&) {
        return;
    }
    throw std::runtime_error(message);
}

void TestRulesAndOwnership() {
    acpp::RoutingConfig config;
    config.domain_strategy = acpp::routing::DomainStrategy::IPIfNonMatch;
    acpp::RouteRuleConfig domain;
    domain.domain_suffix = {"example.com"};
    domain.network = {"tcp"};
    domain.outbound_tag = "domain-proxy";
    acpp::RouteRuleConfig network;
    network.ip = {*acpp::RoutingIpNetwork::Parse("192.0.2.0/24"),
                  *acpp::RoutingIpNetwork::Parse("2001:db8::/32")};
    network.outbound_tag = "ip-proxy";
    config.rules = {domain, network};

    auto router = std::make_unique<Router>(config, nullptr);
    const acpp::routing::Router& query = *router;
    Require(query.DomainStrategy() == acpp::routing::DomainStrategy::IPIfNonMatch,
            "domain strategy must be available through the feature contract");

    acpp::session::Context ctx;
    ctx.content.network = acpp::Network::TCP;
    ctx.outbound.target = acpp::TargetAddress("WWW.EXAMPLE.COM.", 443);
    ctx.outbound.target.resolved_addr = acpp::net::ip::make_address("192.0.2.1");
    const auto domain_match = query.Route(ctx);
    Require(domain_match.matched && domain_match.outbound_tag == "domain-proxy" &&
                domain_match.rule_index == 0,
            "the first matching rule must win over a later IP match");

    ctx.content.network = acpp::Network::UDP;
    auto match = query.Route(ctx);
    Require(match.matched && match.outbound_tag == "ip-proxy" && match.rule_index == 1,
            "UDP must skip a TCP-only rule and retain the actual rule index");
    ctx.outbound.target = acpp::TargetAddress("2001:db8::7", 53);
    Require(query.Route(ctx).outbound_tag == "ip-proxy", "IPv6 routing must match");

    ctx.outbound.target = acpp::TargetAddress("notexample.com", 443);
    ctx.content.network = acpp::Network::TCP;
    match = query.Route(ctx);
    Require(!match.matched && match.outbound_tag.empty(),
            "a suffix boundary miss must return no decision, with no fallback");

    config.rules[0].outbound_tag = "replacement";
    config.domain_strategy = acpp::routing::DomainStrategy::AsIs;
    const Router replacement(config, nullptr);
    config.rules.clear();
    ctx.outbound.target = acpp::TargetAddress("example.com", 443);
    Require(query.Route(ctx).outbound_tag == "domain-proxy" &&
                domain_match.outbound_tag == "domain-proxy" &&
                replacement.Route(ctx).outbound_tag == "replacement" &&
                query.DomainStrategy() == acpp::routing::DomainStrategy::IPIfNonMatch,
            "routers and borrowed decisions must own independent immutable rule data");
}

void TestInvalidConstruction() {
    acpp::RoutingConfig config;
    acpp::RouteRuleConfig valid;
    valid.domain_full = {"example.com"};
    valid.outbound_tag = "direct";
    config.rules.push_back(valid);
    acpp::RouteRuleConfig invalid = valid;
    invalid.domain_regex = {"["};
    config.rules.push_back(invalid);
    RequireThrows<std::regex_error>([&] { Router router(config, nullptr); },
                                   "invalid regex must fail construction");
    config.rules.back() = {};
    config.rules.back().outbound_tag = "direct";
    RequireThrows<std::logic_error>([&] { Router router(config, nullptr); },
                                   "unconditional rule must fail construction");
    config.rules.back() = valid;
    config.rules.back().outbound_tag.clear();
    RequireThrows<std::logic_error>([&] { Router router(config, nullptr); },
                                   "empty outbound tag must fail construction");
    config.rules.back() = valid;
    config.rules.back().geosite = {"cn"};
    RequireThrows<std::logic_error>([&] { Router router(config, nullptr); },
                                   "unresolved geo rules must fail construction");

    const Router empty(acpp::RoutingConfig{}, nullptr);
    Require(!empty.Route(acpp::session::Context{}).matched,
            "an empty router must have no implicit default");
}

}  // namespace

int main() {
    try {
        TestRulesAndOwnership();
        TestInvalidConstruction();
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
    return 0;
}
