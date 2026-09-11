#include "config_semantics.hpp"
#include "acppnode/core/naming.hpp"

#include <vector>

namespace {

acpp::proxyman::outbound::PreparedOutboundConfig Outbound(const char* tag) {
    acpp::proxyman::outbound::PreparedOutboundConfig outbound;
    outbound.tag = tag;
    outbound.protocol = "test";
    return outbound;
}

acpp::RouteRuleConfig Rule(const char* tag) {
    acpp::RouteRuleConfig rule;
    rule.domain_suffix.push_back("example.com");
    rule.outbound_tag = tag;
    return rule;
}

acpp::StaticInboundConfig Inbound(
    const char* tag, const char* listen, uint16_t port) {
    acpp::StaticInboundConfig inbound;
    inbound.tags.push_back(tag);
    inbound.protocol = "vmess";
    inbound.listen = *acpp::InboundListen::Parse(listen);
    inbound.port = port;
    return inbound;
}

}  // namespace

int main() {
    using acpp::ConfigSemanticError;
    using acpp::StaticInboundSemanticError;

    std::vector<acpp::proxyman::outbound::PreparedOutboundConfig> outbounds;
    std::vector<acpp::RouteRuleConfig> rules;

    auto result = acpp::ValidateOutboundRoutingSemantics(outbounds, rules);
    if (result.error != ConfigSemanticError::NoOutbounds) return 1;

    outbounds.push_back(Outbound(""));
    result = acpp::ValidateOutboundRoutingSemantics(outbounds, rules);
    if (result.error != ConfigSemanticError::EmptyOutboundTag || result.index != 0) return 2;

    outbounds[0] = Outbound("direct");
    outbounds.push_back(Outbound("direct"));
    result = acpp::ValidateOutboundRoutingSemantics(outbounds, rules);
    if (result.error != ConfigSemanticError::DuplicateOutboundTag ||
        result.index != 1 || result.tag != "direct") return 3;

    outbounds[1] = Outbound("blackhole");
    rules.push_back(Rule(""));
    result = acpp::ValidateOutboundRoutingSemantics(outbounds, rules);
    if (result.error != ConfigSemanticError::EmptyRouteOutboundTag ||
        result.index != 0) return 4;

    rules[0] = Rule("m2");
    result = acpp::ValidateOutboundRoutingSemantics(outbounds, rules);
    if (result.error != ConfigSemanticError::UnknownRouteOutboundTag ||
        result.index != 0 || result.tag != "m2") return 5;

    rules.push_back(Rule("direct"));
    rules.push_back(Rule("missing"));
    const auto ignored = acpp::IgnoreUnknownRoutingRules(outbounds, rules);
    if (ignored.size() != 2 || ignored[0].index != 0 ||
        ignored[0].tag != "m2" || ignored[1].index != 2 ||
        ignored[1].tag != "missing") return 6;
    if (rules.size() != 1 || rules[0].outbound_tag != "direct") return 7;

    result = acpp::ValidateOutboundRoutingSemantics(outbounds, rules);
    if (!result.Ok()) return 8;

    std::vector<acpp::StaticInboundConfig> inbounds;
    inbounds.push_back(Inbound("first", "127.0.0.1", 0));
    auto inbound_result = acpp::ValidateStaticInboundSemantics(inbounds);
    if (inbound_result.error != StaticInboundSemanticError::InvalidPort ||
        inbound_result.index != 0) return 9;

    inbounds[0] = Inbound("", "127.0.0.1", 12001);
    inbound_result = acpp::ValidateStaticInboundSemantics(inbounds);
    if (inbound_result.error != StaticInboundSemanticError::EmptyTag ||
        inbound_result.index != 0) return 10;

    inbounds[0] = Inbound("same", "127.0.0.1", 12001);
    inbounds.push_back(Inbound("same", "127.0.0.2", 12001));
    inbound_result = acpp::ValidateStaticInboundSemantics(inbounds);
    if (inbound_result.error != StaticInboundSemanticError::DuplicateTag ||
        inbound_result.index != 1 || inbound_result.conflicting_index != 0 ||
        inbound_result.detail != "same") return 11;

    inbounds[1] = Inbound("second", "127.0.0.1", 12001);
    inbound_result = acpp::ValidateStaticInboundSemantics(inbounds);
    if (inbound_result.error != StaticInboundSemanticError::DuplicateEndpoint ||
        inbound_result.index != 1 || inbound_result.conflicting_index != 0) return 12;

    inbounds[0] = Inbound("first", "auto", 12001);
    inbounds[1] = Inbound("second", "0.0.0.0", 12001);
    inbound_result = acpp::ValidateStaticInboundSemantics(inbounds);
    if (inbound_result.error != StaticInboundSemanticError::DuplicateEndpoint ||
        inbound_result.index != 1 || inbound_result.conflicting_index != 0) return 13;

    inbounds[0] = Inbound("first", "127.0.0.1", 12001);
    inbounds[1] = Inbound("second", "127.0.0.2", 12001);
    inbound_result = acpp::ValidateStaticInboundSemantics(inbounds);
    if (!inbound_result.Ok()) return 14;

    for (const char* wildcard : {"0.0.0.0", "auto"}) {
        inbounds[0] = Inbound("first", wildcard, 12001);
        inbounds[1] = Inbound("second", "127.0.0.1", 12001);
        inbound_result = acpp::ValidateStaticInboundSemantics(inbounds);
        if (inbound_result.error != StaticInboundSemanticError::DuplicateEndpoint) return 15;
        std::swap(inbounds[0], inbounds[1]);
        if (acpp::ValidateStaticInboundSemantics(inbounds).error !=
            StaticInboundSemanticError::DuplicateEndpoint) return 16;
    }
    inbounds[0] = Inbound("first", "::", 12001);
    inbounds[1] = Inbound("second", "127.0.0.1", 12001);
    if (!acpp::ValidateStaticInboundSemantics(inbounds).Ok()) return 17;
    inbounds[0] = Inbound("first", "auto", 12002);
    if (!acpp::ValidateStaticInboundSemantics(inbounds).Ok()) return 18;

    const auto first_node = acpp::naming::BuildPanelNodeTag("same-panel", 1, "vmess", 12001);
    const auto second_node = acpp::naming::BuildPanelNodeTag("same-panel", 2, "vmess", 12001);
    if (first_node == second_node || first_node ==
        acpp::naming::BuildPanelNodeTag("other-panel", 1, "vmess", 12001)) return 19;
    inbounds[0].tags[0] = first_node;
    inbound_result = acpp::ValidateStaticInboundSemantics(inbounds);
    if (inbound_result.error != StaticInboundSemanticError::ReservedTag ||
        inbound_result.detail != first_node) return 20;
    outbounds[0].tag = first_node;
    result = acpp::ValidateOutboundRoutingSemantics(outbounds, {});
    if (result.error != ConfigSemanticError::ReservedOutboundTag || result.tag != first_node) return 21;

    return 0;
}
