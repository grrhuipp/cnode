#include "config_semantics.hpp"

#include "core/naming.hpp"

#include <format>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>


ConfigSemanticValidation ValidateOutboundSelectionSemantics(
    std::span<const infra::OutboundSourceConfig> outbounds,
    std::span<const RouteRuleConfig> rules,
    std::span<const StaticInboundConfig> inbounds) {
    if (outbounds.empty()) {
        return {.error = ConfigSemanticError::NoOutbounds, .index = 0, .tag = {}};
    }

    std::unordered_set<std::string_view> tags;
    tags.reserve(outbounds.size());
    for (size_t i = 0; i < outbounds.size(); ++i) {
        const std::string_view tag = outbounds[i].tag;
        if (tag.empty()) {
            return {
                .error = ConfigSemanticError::EmptyOutboundTag,
                .index = i,
                .tag = {},
            };
        }
        if (tag.starts_with(naming::kPanelNodeTagPrefix)) {
            return {.error = ConfigSemanticError::ReservedOutboundTag, .index = i, .tag = tag};
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
                .tag = {},
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

    for (size_t i = 0; i < inbounds.size(); ++i) {
        if (!inbounds[i].outbound_tag) continue;
        const std::string_view tag = *inbounds[i].outbound_tag;
        if (tag.empty()) {
            return {
                .error = ConfigSemanticError::EmptyStaticInboundOutboundTag,
                .index = i,
                .tag = tag,
            };
        }
        if (!tags.contains(tag)) {
            return {
                .error = ConfigSemanticError::UnknownStaticInboundOutboundTag,
                .index = i,
                .tag = tag,
            };
        }
    }

    return {};
}

std::string StaticInboundSemanticValidation::Message() const {
    switch (error) {
        case StaticInboundSemanticError::None: return {};
        case StaticInboundSemanticError::InvalidPort:
            return std::format("at index {} has an invalid port", index);
        case StaticInboundSemanticError::EmptyTag:
            return std::format("at index {} has an empty tag", index);
        case StaticInboundSemanticError::ReservedTag:
            return std::format("at index {} uses reserved panel tag '{}'", index, detail);
        case StaticInboundSemanticError::DuplicateTag:
            return std::format("at index {} duplicates tag '{}' from index {}", index, detail, conflicting_index);
        case StaticInboundSemanticError::DuplicateEndpoint:
            return std::format("at index {} duplicates listen endpoint '{}' from index {}", index, detail, conflicting_index);
    }
    throw std::logic_error("unknown static inbound validation result");
}

StaticInboundSemanticValidation ValidateStaticInboundSemantics(
    std::span<const StaticInboundConfig> inbounds) {
    std::unordered_map<std::string, size_t> tags;
    tags.reserve(inbounds.size());

    for (size_t i = 0; i < inbounds.size(); ++i) {
        const auto& inbound = inbounds[i];
        if (inbound.port == 0) {
            return {
                .error = StaticInboundSemanticError::InvalidPort,
                .index = i,
                .conflicting_index = 0,
                .detail = {},
            };
        }

        auto validate_tag = [&](std::string tag) -> StaticInboundSemanticValidation {
            if (tag.empty()) {
                return {
                    .error = StaticInboundSemanticError::EmptyTag,
                    .index = i,
                    .conflicting_index = 0,
                    .detail = {},
                };
            }
            if (tag.starts_with(naming::kPanelNodeTagPrefix)) {
                return {.error = StaticInboundSemanticError::ReservedTag,
                        .index = i, .conflicting_index = 0, .detail = std::move(tag)};
            }
            if (const auto [it, inserted] = tags.emplace(std::move(tag), i); !inserted) {
                return {
                    .error = StaticInboundSemanticError::DuplicateTag,
                    .index = i,
                    .conflicting_index = it->second,
                    .detail = it->first,
                };
            }
            return {};
        };

        if (inbound.tags.empty()) {
            if (auto err = validate_tag(
                    naming::BuildProtocolPortTag(inbound.protocol, inbound.port));
                !err.Ok()) {
                return err;
            }
        } else {
            for (const auto& tag : inbound.tags) {
                if (auto err = validate_tag(tag); !err.Ok()) {
                    return err;
                }
            }
        }

        for (size_t previous = 0; previous < i; ++previous) {
            if (inbounds[previous].port == inbound.port &&
                inbounds[previous].listen.Overlaps(inbound.listen)) {
                return {
                    .error = StaticInboundSemanticError::DuplicateEndpoint,
                    .index = i,
                    .conflicting_index = previous,
                    .detail = std::to_string(inbound.port),
                };
            }
        }
    }

    return {};
}

