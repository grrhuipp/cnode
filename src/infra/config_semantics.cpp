#include "config_semantics.hpp"

#include "core/naming.hpp"
#include "infra/config.hpp"
#include "infra/log.hpp"
#include <algorithm>

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

namespace {

std::vector<std::string> GetUsedRouteRuleTags(
    const RoutingConfig& routing,
    const std::vector<std::string> RouteRuleConfig::* field) {
    std::vector<std::string> tags;
    for (const auto& rule : routing.rules) {
        for (const auto& tag : rule.*field) {
            if (std::ranges::find(tags, tag) == tags.end()) {
                tags.push_back(tag);
            }
        }
    }
    return tags;
}

}  // namespace

bool ValidateConfig(const Config& config) {
    if (config.workers == 0 || config.workers > defaults::kMaxWorkers) {
        LOG_CONSOLE_ERROR("Worker count must be between 1 and {}", defaults::kMaxWorkers);
        return false;
    }

    if (config.dns.servers.empty()) {
        LOG_CONSOLE_ERROR("At least one DNS server is required");
        return false;
    }

    if (config.timeouts.handshake == 0 ||
        config.timeouts.dial == 0 ||
        config.timeouts.read == 0 ||
        config.timeouts.write == 0 ||
        config.timeouts.idle == 0 ||
        config.timeouts.uplink_only == 0 ||
        config.timeouts.downlink_only == 0 ||
        config.dns.timeout == 0) {
        LOG_CONSOLE_ERROR("Timeout values must be positive");
        return false;
    }

    if (config.dns.min_ttl > config.dns.max_ttl) {
        LOG_CONSOLE_ERROR("DNS minTTL must be less than or equal to maxTTL");
        return false;
    }

    std::unordered_set<std::string> panel_nodes;
    for (const auto& panel : config.panels) {
        if (!panel.Validate()) {
            return false;
        }
        for (const int node_id : panel.NodeIDs.Values()) {
            auto key = naming::BuildPanelNodeAccountingKey(panel.Name, node_id);
            if (!panel_nodes.insert(key).second) {
                const PanelLogContext log_context{panel.Name, panel.APIHost, node_id, panel.NodeType};
                LOG_PANEL_ERROR(log_context, "Duplicate panel node identity");
                return false;
            }
        }
    }

    const auto inbound_semantic = ValidateStaticInboundSemantics(config.static_inbounds);
    if (!inbound_semantic.Ok()) {
        LOG_CONSOLE_ERROR("Static inbound {}", inbound_semantic.Message());
        return false;
    }

    const auto semantic = ValidateOutboundSelectionSemantics(
        config.outbounds, config.routing.rules, config.static_inbounds);
    switch (semantic.error) {
        case ConfigSemanticError::None:
            break;
        case ConfigSemanticError::NoOutbounds:
            LOG_CONSOLE_ERROR("At least one outbound is required");
            return false;
        case ConfigSemanticError::EmptyOutboundTag:
            LOG_CONSOLE_ERROR("Outbound at index {} has an empty tag", semantic.index);
            return false;
        case ConfigSemanticError::ReservedOutboundTag:
            LOG_CONSOLE_ERROR("Outbound at index {} uses reserved panel tag '{}'", semantic.index, semantic.tag);
            return false;
        case ConfigSemanticError::DuplicateOutboundTag:
            LOG_CONSOLE_ERROR("Duplicate outbound tag '{}' at index {}",
                      semantic.tag, semantic.index);
            return false;
        case ConfigSemanticError::EmptyRouteOutboundTag:
            LOG_CONSOLE_ERROR("Routing rule at index {} has an empty outbound tag",
                      semantic.index);
            return false;
        case ConfigSemanticError::UnknownRouteOutboundTag:
            LOG_CONSOLE_ERROR("Routing rule at index {} references unknown outbound '{}'",
                      semantic.index, semantic.tag);
            return false;
        case ConfigSemanticError::EmptyStaticInboundOutboundTag:
            LOG_CONSOLE_ERROR("Static inbound at index {} has an empty outboundTag", semantic.index);
            return false;
        case ConfigSemanticError::UnknownStaticInboundOutboundTag:
            LOG_CONSOLE_ERROR("Static inbound at index {} references unknown outboundTag '{}'",
                      semantic.index, semantic.tag);
            return false;
    }

    return true;
}

std::vector<std::string> GetUsedGeoIPTags(const RoutingConfig& routing) {
    return GetUsedRouteRuleTags(routing, &RouteRuleConfig::geoip);
}

std::vector<std::string> GetUsedGeoSiteTags(const RoutingConfig& routing) {
    return GetUsedRouteRuleTags(routing, &RouteRuleConfig::geosite);
}

