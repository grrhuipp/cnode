#include "config_semantics.hpp"

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

}  // namespace

int main() {
    using acpp::ConfigSemanticError;

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

    rules[0] = Rule("direct");
    result = acpp::ValidateOutboundRoutingSemantics(outbounds, rules);
    if (!result.Ok()) return 6;

    return 0;
}
