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

    rules[0] = Rule("direct");
    result = acpp::ValidateOutboundRoutingSemantics(outbounds, rules);
    if (!result.Ok()) return 6;

    std::vector<acpp::StaticInboundConfig> inbounds;
    inbounds.push_back(Inbound("first", "127.0.0.1", 0));
    auto inbound_result = acpp::ValidateStaticInboundSemantics(inbounds);
    if (inbound_result.error != StaticInboundSemanticError::InvalidPort ||
        inbound_result.index != 0) return 7;

    inbounds[0] = Inbound("", "127.0.0.1", 12001);
    inbound_result = acpp::ValidateStaticInboundSemantics(inbounds);
    if (inbound_result.error != StaticInboundSemanticError::EmptyTag ||
        inbound_result.index != 0) return 8;

    inbounds[0] = Inbound("same", "127.0.0.1", 12001);
    inbounds.push_back(Inbound("same", "127.0.0.2", 12001));
    inbound_result = acpp::ValidateStaticInboundSemantics(inbounds);
    if (inbound_result.error != StaticInboundSemanticError::DuplicateTag ||
        inbound_result.index != 1 || inbound_result.conflicting_index != 0 ||
        inbound_result.detail != "same") return 9;

    inbounds[1] = Inbound("second", "127.0.0.1", 12001);
    inbound_result = acpp::ValidateStaticInboundSemantics(inbounds);
    if (inbound_result.error != StaticInboundSemanticError::DuplicateEndpoint ||
        inbound_result.index != 1 || inbound_result.conflicting_index != 0) return 10;

    inbounds[0] = Inbound("first", "auto", 12001);
    inbounds[1] = Inbound("second", "0.0.0.0", 12001);
    inbound_result = acpp::ValidateStaticInboundSemantics(inbounds);
    if (inbound_result.error != StaticInboundSemanticError::DuplicateEndpoint ||
        inbound_result.index != 1 || inbound_result.conflicting_index != 0) return 11;

    inbounds[0] = Inbound("first", "127.0.0.1", 12001);
    inbounds[1] = Inbound("second", "127.0.0.2", 12001);
    inbound_result = acpp::ValidateStaticInboundSemantics(inbounds);
    if (!inbound_result.Ok()) return 12;

    return 0;
}
