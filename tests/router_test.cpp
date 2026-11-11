#include <gtest/gtest.h>

#include "app/router/router.hpp"
#include "app/proxyman/inbound/handler.hpp"
#include "common/session.hpp"
#include "infra/config_types.hpp"

#include <concepts>
#include <cstddef>
#include <iostream>
#include <memory>
#include <memory_resource>
#include <regex>
#include <stdexcept>

namespace {

using ::app::router::Router;

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
    ::RoutingConfig config;
    config.domain_strategy = ::routing::DomainStrategy::IPIfNonMatch;
    ::RouteRuleConfig domain;
    domain.domain_suffix = {"example.com"};
    domain.network = {"tcp"};
    domain.outbound_tag = "domain-proxy";
    ::RouteRuleConfig network;
    network.ip = {*::RoutingIpNetwork::Parse("192.0.2.0/24"),
                  *::RoutingIpNetwork::Parse("2001:db8::/32")};
    network.outbound_tag = "ip-proxy";
    config.rules = {domain, network};

    auto router = std::make_unique<Router>(config, nullptr);
    const ::routing::Router& query = *router;
    Require(query.DomainStrategy() == ::routing::DomainStrategy::IPIfNonMatch,
            "domain strategy must be available through the feature contract");
    ::session::Context ctx;
    ctx.content.network = ::Network::TCP;
    ctx.outbound.target = ::TargetAddress("WWW.EXAMPLE.COM.", 443);
    ctx.outbound.target.resolved_addr = ::net::ip::make_address("192.0.2.1");
    const auto domain_match = query.Route(ctx);
    Require(domain_match.matched && domain_match.outbound_tag == "domain-proxy",
            "the first matching rule must win over a later IP match");

    ctx.content.network = ::Network::UDP;
    auto match = query.Route(ctx);
    Require(match.matched && match.outbound_tag == "ip-proxy",
            "UDP must skip a TCP-only rule");
    ctx.outbound.target = ::TargetAddress("2001:db8::7", 53);
    Require(query.Route(ctx).outbound_tag == "ip-proxy", "IPv6 routing must match");

    // route_only (route_target) must participate in port and IP matching.
    ::RouteRuleConfig port_rule;
    port_rule.port = {::RoutingPortRange{8443, 8443}};
    port_rule.outbound_tag = "port-proxy";
    ::RoutingConfig port_cfg;
    port_cfg.rules = {port_rule, network};
    const Router port_router(port_cfg, nullptr);
    ctx.outbound.target = ::TargetAddress("example.org", 80);
    ctx.outbound.route_target = ::TargetAddress("sniffed.example.org", 8443);
    Require(port_router.Route(ctx).outbound_tag == "port-proxy",
            "route_target port must match port routing rule when route_only is enabled");
    ctx.outbound.route_target = ::TargetAddress("sniffed.example.org", 443);
    ctx.outbound.route_target.resolved_addr = ::net::ip::make_address("192.0.2.99");
    Require(port_router.Route(ctx).outbound_tag == "ip-proxy",
            "route_target resolved_addr must match IP routing rule when route_only is enabled");
    ctx.outbound.route_target = {};
    ctx.outbound.target = ::TargetAddress("notexample.com", 443);
    ctx.content.network = ::Network::TCP;
    match = query.Route(ctx);
    Require(!match.matched && match.outbound_tag.empty(),
            "a suffix boundary miss must return no decision, with no fallback");

    config.rules[0].outbound_tag = "replacement";
    config.domain_strategy = ::routing::DomainStrategy::AsIs;
    const Router replacement(config, nullptr);
    config.rules.clear();
    ctx.outbound.target = ::TargetAddress("example.com", 443);
    Require(query.Route(ctx).outbound_tag == "domain-proxy" &&
                domain_match.outbound_tag == "domain-proxy" &&
                replacement.Route(ctx).outbound_tag == "replacement" &&
                query.DomainStrategy() == ::routing::DomainStrategy::IPIfNonMatch,
            "routers and borrowed decisions must own independent immutable rule data");
}

void TestInboundMetadataOwnershipAndRouting() {
    using ::session::Context;
    {
        {
            {
                Context ctx;
                Context copy;
                {
                    ::proxyman::inbound::ReceiverSettings receiver{
                        .inbound_tag = {}, .inbound_tags = {}, .protocol = {},
                        .stream_settings = {},
                        .dispatch_policy = {
                            .sniffing = {},
                            .outbound = ::routing::ForceOutbound{"metadata-test"}}};
                    receiver.inbound_tag = std::string(96, 'm');
                    receiver.inbound_tags = {receiver.inbound_tag, std::string(112, 'x')};
                    receiver.protocol = std::string(104, 'p');
                    receiver.stream_settings.security = std::string(108, 's');
                    ctx.inbound.tag = receiver.inbound_tag;
                    ctx.inbound.accounting_key = receiver.protocol;
                    ctx.inbound.user_email = receiver.stream_settings.security;
                    for (const auto& tag : receiver.inbound_tags) {
                        ctx.inbound.tags.emplace_back(tag);
                    }
                    copy.inbound = ctx.inbound;
                }

                Require(ctx.inbound.tag.size() == 96 && ctx.inbound.accounting_key.size() == 104 &&
                            ctx.inbound.user_email.size() == 108 && ctx.inbound.tags.size() == 2 &&
                            ctx.inbound.tags[1].size() == 112,
                        "inbound metadata must outlive its cold receiver source");
                Require(ctx.inbound.tag.get_allocator().resource() == ::memory::process_resource() &&
                            ctx.inbound.accounting_key.get_allocator().resource() == ::memory::process_resource() &&
                            ctx.inbound.user_email.get_allocator().resource() == ::memory::process_resource() &&
                            ctx.inbound.tags.get_allocator().resource() == ::memory::process_resource() &&
                            ctx.inbound.tags[0].get_allocator().resource() == ::memory::process_resource() &&
                            copy.inbound.tag.get_allocator().resource() == ::memory::process_resource() &&
                            copy.inbound.tags[0].get_allocator().resource() == ::memory::process_resource(),
                        "inbound metadata and Context copies must use the process resource");
                ctx.inbound.tag[0] = 'c';
                ctx.outbound.target = ::TargetAddress("2001:db8:85a3::8a2e:370:7334", 443);
                Require(ctx.outbound.target.IsIPv6() &&
                            ctx.outbound.target.host.empty(),
                        "IPv6 literal TargetAddress must use its inline address representation");
                ctx.inbound.tags[1][0] = 'y';
                Require(copy.inbound.tag[0] == 'm' && copy.inbound.tags[1][0] == 'x',
                        "copied inbound metadata must be independent owned values");
            }
        }
    }

    ::RoutingConfig config;
    ::RouteRuleConfig main_tag;
    main_tag.inbound_tag = {std::string(96, 'm')};
    main_tag.domain_full = {"main.example"};
    main_tag.outbound_tag = "main-out";
    ::RouteRuleConfig extra_tag;
    extra_tag.inbound_tag = {std::string(112, 'x')};
    extra_tag.domain_full = {"extra.example"};
    extra_tag.outbound_tag = "extra-out";
    config.rules = {main_tag, extra_tag};
    const Router router(config, nullptr);
    Context routed;
    routed.inbound.tag = std::string(96, 'm');
    routed.inbound.tags.emplace_back(std::string(112, 'x'));
    routed.outbound.target = ::TargetAddress("main.example", 443);
    Require(router.Route(routed).outbound_tag == "main-out",
            "primary inbound tag must match its rule");
    routed.outbound.target = ::TargetAddress("extra.example", 443);
    Require(router.Route(routed).outbound_tag == "extra-out",
            "non-empty extra tags must participate in routing");
    routed.inbound.tags.clear();
    Require(!router.Route(routed).matched,
            "empty extra tags must mean no additional inbound tags");
}

void TestInvalidConstruction() {
    ::RoutingConfig config;
    ::RouteRuleConfig valid;
    valid.domain_full = {"example.com"};
    valid.outbound_tag = "direct";
    config.rules.push_back(valid);
    ::RouteRuleConfig invalid = valid;
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

    const Router empty(::RoutingConfig{}, nullptr);
    Require(!empty.Route(::session::Context{}).matched,
            "an empty router must have no implicit default");
}

}  // namespace

TEST(Router, Contract) {
    try {
        TestRulesAndOwnership();
        TestInboundMetadataOwnershipAndRouting();
        TestInvalidConstruction();
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        FAIL() << error.what();
    }
}
