#include "config_semantics.hpp"

#include <string_view>
#include <unordered_set>

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

}  // namespace acpp
