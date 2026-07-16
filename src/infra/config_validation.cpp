#include "acppnode/infra/config.hpp"
#include "acppnode/infra/log.hpp"

#include "config_semantics.hpp"

#include <algorithm>

namespace acpp {

bool Config::Validate() const {
    if (workers_ == 0 || workers_ > defaults::kMaxWorkers) {
        LOG_ERROR("Worker count must be between 1 and {}", defaults::kMaxWorkers);
        return false;
    }

    if (dns_.servers.empty()) {
        LOG_ERROR("At least one DNS server is required");
        return false;
    }

    if (timeouts_.handshake == 0 || timeouts_.dial == 0) {
        LOG_ERROR("Timeout values must be positive");
        return false;
    }

    if (dns_.min_ttl > dns_.max_ttl) {
        LOG_ERROR("DNS minTTL must be less than or equal to maxTTL");
        return false;
    }

    const auto inbound_semantic = ValidateStaticInboundSemantics(static_inbounds_);
    switch (inbound_semantic.error) {
        case StaticInboundSemanticError::None:
            break;
        case StaticInboundSemanticError::InvalidPort:
            LOG_ERROR("Static inbound at index {} has an invalid port", inbound_semantic.index);
            return false;
        case StaticInboundSemanticError::EmptyTag:
            LOG_ERROR("Static inbound at index {} has an empty tag", inbound_semantic.index);
            return false;
        case StaticInboundSemanticError::DuplicateTag:
            LOG_ERROR("Static inbound at index {} duplicates tag '{}' from index {}",
                      inbound_semantic.index, inbound_semantic.detail,
                      inbound_semantic.conflicting_index);
            return false;
        case StaticInboundSemanticError::DuplicateEndpoint:
            LOG_ERROR("Static inbound at index {} duplicates listen endpoint '{}' from index {}",
                      inbound_semantic.index, inbound_semantic.detail,
                      inbound_semantic.conflicting_index);
            return false;
    }

    const auto semantic = ValidateOutboundRoutingSemantics(
        prepared_outbounds_, routing_.rules);
    switch (semantic.error) {
        case ConfigSemanticError::None:
            break;
        case ConfigSemanticError::NoOutbounds:
            LOG_ERROR("At least one outbound is required");
            return false;
        case ConfigSemanticError::EmptyOutboundTag:
            LOG_ERROR("Outbound at index {} has an empty tag", semantic.index);
            return false;
        case ConfigSemanticError::DuplicateOutboundTag:
            LOG_ERROR("Duplicate outbound tag '{}' at index {}",
                      semantic.tag, semantic.index);
            return false;
        case ConfigSemanticError::EmptyRouteOutboundTag:
            LOG_ERROR("Routing rule at index {} has an empty outbound tag",
                      semantic.index);
            return false;
        case ConfigSemanticError::UnknownRouteOutboundTag:
            LOG_ERROR("Routing rule at index {} references unknown outbound '{}'",
                      semantic.index, semantic.tag);
            return false;
    }

    return true;
}

std::vector<std::string> Config::GetUsedGeoIPTags() const {
    std::vector<std::string> tags;
    for (const auto& rule : routing_.rules) {
        for (const auto& tag : rule.geoip) {
            if (!std::ranges::contains(tags, tag)) {
                tags.push_back(tag);
            }
        }
    }
    return tags;
}

std::vector<std::string> Config::GetUsedGeoSiteTags() const {
    std::vector<std::string> tags;
    for (const auto& rule : routing_.rules) {
        for (const auto& tag : rule.geosite) {
            if (!std::ranges::contains(tags, tag)) {
                tags.push_back(tag);
            }
        }
    }
    return tags;
}

}  // namespace acpp
