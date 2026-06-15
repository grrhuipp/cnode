#include "acppnode/infra/config.hpp"
#include "acppnode/infra/log.hpp"

#include <algorithm>

namespace acpp {

bool Config::Validate() const {
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
