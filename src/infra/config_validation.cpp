#include "acppnode/infra/config.hpp"
#include "acppnode/core/naming.hpp"
#include "acppnode/infra/log.hpp"

#include "config_semantics.hpp"

#include <algorithm>
#include <unordered_set>

namespace acpp {

bool ValidateConfig(const Config& config) {
    if (config.workers == 0 || config.workers > defaults::kMaxWorkers) {
        LOG_CONSOLE_ERROR("Worker count must be between 1 and {}", defaults::kMaxWorkers);
        return false;
    }

    if (config.dns.servers.empty()) {
        LOG_CONSOLE_ERROR("At least one DNS server is required");
        return false;
    }

    if (config.timeouts.handshake == 0 || config.timeouts.dial == 0) {
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
            auto key = naming::BuildPanelNodeStatsKey(panel.Name, node_id);
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
    std::vector<std::string> tags;
    for (const auto& rule : routing.rules) {
        for (const auto& tag : rule.geoip) {
            if (std::ranges::find(tags, tag) == tags.end()) {
                tags.push_back(tag);
            }
        }
    }
    return tags;
}

std::vector<std::string> GetUsedGeoSiteTags(const RoutingConfig& routing) {
    std::vector<std::string> tags;
    for (const auto& rule : routing.rules) {
        for (const auto& tag : rule.geosite) {
            if (std::ranges::find(tags, tag) == tags.end()) {
                tags.push_back(tag);
            }
        }
    }
    return tags;
}

}  // namespace acpp
