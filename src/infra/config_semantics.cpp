#include "config_semantics.hpp"

#include "acppnode/core/naming.hpp"

#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace acpp {

ConfigSemanticValidation ValidateOutboundRoutingSemantics(
    std::span<const proxyman::outbound::PreparedOutboundConfig> outbounds,
    std::span<const RouteRuleConfig> rules) {
    if (outbounds.empty()) {
        return {.error = ConfigSemanticError::NoOutbounds};
    }

    std::unordered_set<std::string_view> tags;
    tags.reserve(outbounds.size());
    for (size_t i = 0; i < outbounds.size(); ++i) {
        const std::string_view tag = outbounds[i].tag;
        if (tag.empty()) {
            return {
                .error = ConfigSemanticError::EmptyOutboundTag,
                .index = i,
            };
        }
        if (!tags.insert(tag).second) {
            return {
                .error = ConfigSemanticError::DuplicateOutboundTag,
                .index = i,
                .tag = tag,
            };
        }
    }

    for (size_t i = 0; i < rules.size(); ++i) {
        const std::string_view tag = rules[i].outbound_tag;
        if (tag.empty()) {
            return {
                .error = ConfigSemanticError::EmptyRouteOutboundTag,
                .index = i,
            };
        }
        if (!tags.contains(tag)) {
            return {
                .error = ConfigSemanticError::UnknownRouteOutboundTag,
                .index = i,
                .tag = tag,
            };
        }
    }

    return {};
}

std::vector<IgnoredRouteRule> IgnoreUnknownRoutingRules(
    std::span<const proxyman::outbound::PreparedOutboundConfig> outbounds,
    std::vector<RouteRuleConfig>& rules) {
    std::unordered_set<std::string_view> tags;
    tags.reserve(outbounds.size());
    for (const auto& outbound : outbounds) {
        tags.insert(outbound.tag);
    }

    std::vector<IgnoredRouteRule> ignored;
    ignored.reserve(rules.size());
    size_t index = 0;
    std::erase_if(rules, [&](const RouteRuleConfig& rule) {
        const bool unknown = !rule.outbound_tag.empty() &&
                             !tags.contains(rule.outbound_tag);
        if (unknown) {
            ignored.push_back(IgnoredRouteRule{
                .index = index,
                .tag = rule.outbound_tag,
            });
        }
        ++index;
        return unknown;
    });
    return ignored;
}

StaticInboundSemanticValidation ValidateStaticInboundSemantics(
    std::span<const StaticInboundConfig> inbounds) {
    std::unordered_map<std::string, size_t> tags;
    std::unordered_map<std::string, size_t> endpoints;
    tags.reserve(inbounds.size());
    endpoints.reserve(inbounds.size() * 2);

    for (size_t i = 0; i < inbounds.size(); ++i) {
        const auto& inbound = inbounds[i];
        if (inbound.port == 0) {
            return {
                .error = StaticInboundSemanticError::InvalidPort,
                .index = i,
            };
        }

        std::string tag = inbound.tags.empty()
            ? naming::BuildProtocolPortTag(inbound.protocol, inbound.port)
            : inbound.tags.front();
        if (tag.empty()) {
            return {
                .error = StaticInboundSemanticError::EmptyTag,
                .index = i,
            };
        }
        if (const auto [it, inserted] = tags.emplace(tag, i); !inserted) {
            return {
                .error = StaticInboundSemanticError::DuplicateTag,
                .index = i,
                .conflicting_index = it->second,
                .detail = std::move(tag),
            };
        }

        for (const auto& address : inbound.listen.Candidates()) {
            std::string endpoint = address.to_string();
            endpoint.push_back('|');
            endpoint.append(std::to_string(inbound.port));
            if (const auto [it, inserted] = endpoints.emplace(endpoint, i); !inserted) {
                return {
                    .error = StaticInboundSemanticError::DuplicateEndpoint,
                    .index = i,
                    .conflicting_index = it->second,
                    .detail = std::move(endpoint),
                };
            }
        }
    }

    return {};
}

}  // namespace acpp
