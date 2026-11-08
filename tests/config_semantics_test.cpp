#include <gtest/gtest.h>

#include "config_semantics.hpp"
#include "core/naming.hpp"

#include <vector>

namespace {

::infra::OutboundSourceConfig Outbound(const char* tag) {
    ::infra::OutboundSourceConfig outbound;
    outbound.tag = tag;
    outbound.protocol = "test";
    return outbound;
}

::RouteRuleConfig Rule(const char* tag) {
    ::RouteRuleConfig rule;
    rule.domain_suffix.push_back("example.com");
    rule.outbound_tag = tag;
    return rule;
}

::StaticInboundConfig Inbound(
    const char* tag, const char* listen, uint16_t port) {
    ::StaticInboundConfig inbound;
    inbound.tags.push_back(tag);
    inbound.protocol = "vmess";
    inbound.listen = *::InboundListen::Parse(listen);
    inbound.port = port;
    return inbound;
}

}  // namespace

TEST(ConfigSemantics, Contract) {
    using ::ConfigSemanticError;
    using ::StaticInboundSemanticError;

    std::vector<::infra::OutboundSourceConfig> outbounds;
    std::vector<::RouteRuleConfig> rules;

    auto result = ::ValidateOutboundSelectionSemantics(outbounds, rules, {});
    ASSERT_FALSE((result.error != ConfigSemanticError::NoOutbounds));

    outbounds.push_back(Outbound(""));
    result = ::ValidateOutboundSelectionSemantics(outbounds, rules, {});
    ASSERT_FALSE((result.error != ConfigSemanticError::EmptyOutboundTag || result.index != 0));

    outbounds[0] = Outbound("direct");
    outbounds.push_back(Outbound("direct"));
    result = ::ValidateOutboundSelectionSemantics(outbounds, rules, {});
    ASSERT_FALSE((result.error != ConfigSemanticError::DuplicateOutboundTag ||
        result.index != 1 || result.tag != "direct"));

    outbounds[1] = Outbound("blackhole");
    rules.push_back(Rule(""));
    result = ::ValidateOutboundSelectionSemantics(outbounds, rules, {});
    ASSERT_FALSE((result.error != ConfigSemanticError::EmptyRouteOutboundTag ||
        result.index != 0));

    rules[0] = Rule("m2");
    result = ::ValidateOutboundSelectionSemantics(outbounds, rules, {});
    ASSERT_FALSE((result.error != ConfigSemanticError::UnknownRouteOutboundTag ||
        result.index != 0 || result.tag != "m2"));

    rules.push_back(Rule("direct"));
    rules.push_back(Rule("missing"));
    result = ::ValidateOutboundSelectionSemantics(outbounds, rules, {});
    ASSERT_FALSE((result.error != ConfigSemanticError::UnknownRouteOutboundTag ||
        result.index != 0 || rules.size() != 3));
    rules = {Rule("direct")};

    result = ::ValidateOutboundSelectionSemantics(outbounds, rules, {});
    ASSERT_FALSE((!result.Ok()));

    std::vector<::StaticInboundConfig> inbounds;
    inbounds.push_back(Inbound("first", "127.0.0.1", 0));
    auto inbound_result = ::ValidateStaticInboundSemantics(inbounds);
    ASSERT_FALSE((inbound_result.error != StaticInboundSemanticError::InvalidPort ||
        inbound_result.index != 0));

    inbounds[0] = Inbound("", "127.0.0.1", 12001);
    inbound_result = ::ValidateStaticInboundSemantics(inbounds);
    ASSERT_FALSE((inbound_result.error != StaticInboundSemanticError::EmptyTag ||
        inbound_result.index != 0));

    inbounds[0] = Inbound("same", "127.0.0.1", 12001);
    inbounds.push_back(Inbound("same", "127.0.0.2", 12001));
    inbound_result = ::ValidateStaticInboundSemantics(inbounds);
    ASSERT_FALSE((inbound_result.error != StaticInboundSemanticError::DuplicateTag ||
        inbound_result.index != 1 || inbound_result.conflicting_index != 0 ||
        inbound_result.detail != "same"));

    inbounds[1] = Inbound("second", "127.0.0.1", 12001);
    inbound_result = ::ValidateStaticInboundSemantics(inbounds);
    ASSERT_FALSE((inbound_result.error != StaticInboundSemanticError::DuplicateEndpoint ||
        inbound_result.index != 1 || inbound_result.conflicting_index != 0));

    inbounds[0] = Inbound("first", "auto", 12001);
    inbounds[1] = Inbound("second", "0.0.0.0", 12001);
    inbound_result = ::ValidateStaticInboundSemantics(inbounds);
    ASSERT_FALSE((inbound_result.error != StaticInboundSemanticError::DuplicateEndpoint ||
        inbound_result.index != 1 || inbound_result.conflicting_index != 0));

    inbounds[0] = Inbound("first", "127.0.0.1", 12001);
    inbounds[1] = Inbound("second", "127.0.0.2", 12001);
    inbound_result = ::ValidateStaticInboundSemantics(inbounds);
    ASSERT_FALSE((!inbound_result.Ok()));

    for (const char* wildcard : {"0.0.0.0", "auto"}) {
        inbounds[0] = Inbound("first", wildcard, 12001);
        inbounds[1] = Inbound("second", "127.0.0.1", 12001);
        inbound_result = ::ValidateStaticInboundSemantics(inbounds);
        ASSERT_FALSE((inbound_result.error != StaticInboundSemanticError::DuplicateEndpoint));
        std::swap(inbounds[0], inbounds[1]);
        ASSERT_FALSE((::ValidateStaticInboundSemantics(inbounds).error !=
            StaticInboundSemanticError::DuplicateEndpoint));
    }
    inbounds[0] = Inbound("first", "::", 12001);
    inbounds[1] = Inbound("second", "127.0.0.1", 12001);
    ASSERT_FALSE((!::ValidateStaticInboundSemantics(inbounds).Ok()));
    inbounds[0] = Inbound("first", "auto", 12002);
    ASSERT_FALSE((!::ValidateStaticInboundSemantics(inbounds).Ok()));

    const auto first_node = ::naming::BuildPanelNodeTag("same-panel", 1, "vmess", 12001);
    const auto second_node = ::naming::BuildPanelNodeTag("same-panel", 2, "vmess", 12001);
    ASSERT_FALSE((first_node == second_node || first_node ==
        ::naming::BuildPanelNodeTag("other-panel", 1, "vmess", 12001)));
    inbounds[0].tags[0] = first_node;
    inbound_result = ::ValidateStaticInboundSemantics(inbounds);
    ASSERT_FALSE((inbound_result.error != StaticInboundSemanticError::ReservedTag ||
        inbound_result.detail != first_node));
    outbounds[0].tag = first_node;
    result = ::ValidateOutboundSelectionSemantics(outbounds, {}, {});
    ASSERT_FALSE((result.error != ConfigSemanticError::ReservedOutboundTag || result.tag != first_node));

    outbounds[0].tag = "direct";
    inbounds.resize(1);
    inbounds[0] = Inbound("forced", "127.0.0.1", 12001);
    inbounds[0].outbound_tag = "blackhole";
    result = ::ValidateOutboundSelectionSemantics(outbounds, rules, inbounds);
    ASSERT_FALSE((!result.Ok()));
    inbounds[0].outbound_tag = "";
    result = ::ValidateOutboundSelectionSemantics(outbounds, {}, inbounds);
    ASSERT_FALSE((result.error != ConfigSemanticError::EmptyStaticInboundOutboundTag || result.index != 0));
    inbounds[0].outbound_tag = "missing";
    result = ::ValidateOutboundSelectionSemantics(outbounds, {}, inbounds);
    ASSERT_FALSE((result.error != ConfigSemanticError::UnknownStaticInboundOutboundTag ||
        result.index != 0 || result.tag != "missing"));
    inbounds[0].outbound_tag.reset();
    ASSERT_FALSE((!::ValidateOutboundSelectionSemantics(outbounds, {}, inbounds).Ok()));

}
