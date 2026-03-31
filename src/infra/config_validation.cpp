#include "acppnode/infra/config.hpp"
#include "acppnode/infra/log.hpp"

#include <algorithm>

namespace acpp {

bool Config::Validate() const {
    for (const auto& panel : panels_) {
        if (panel.name.empty()) {
            LOG_ERROR("Panel name is required");
            return false;
        }
        if (panel.api_host.empty()) {
            LOG_ERROR("Panel {} ApiHost is required", panel.name);
            return false;
        }
        if (panel.api_key.empty()) {
            LOG_ERROR("Panel {} ApiKey is required", panel.name);
            return false;
        }
        if (panel.node_ids.empty()) {
            LOG_ERROR("Panel {} NodeID is required", panel.name);
            return false;
        }
        if (panel.type != constants::panel::kV2BoardType) {
            LOG_ERROR("Panel {} Type must be {}", panel.name, constants::panel::kV2BoardType);
            return false;
        }
        if (panel.node_type != constants::protocol::kVmess &&
            panel.node_type != constants::protocol::kTrojan &&
            panel.node_type != constants::protocol::kShadowsocks) {
            LOG_ERROR("Panel {} NodeType must be {}, {} or {}",
                      panel.name,
                      constants::protocol::kVmess,
                      constants::protocol::kTrojan,
                      constants::protocol::kShadowsocks);
            return false;
        }
        if (panel.tls_enable) {
            if (!panel.tls_cert.empty() && !std::filesystem::exists(panel.tls_cert)) {
                LOG_ERROR("Panel {} TlsCert not found: {}", panel.name, panel.tls_cert);
                return false;
            }
            if (!panel.tls_key.empty() && !std::filesystem::exists(panel.tls_key)) {
                LOG_ERROR("Panel {} TlsKey not found: {}", panel.name, panel.tls_key);
                return false;
            }
        }
    }

    if (dns_.servers.empty()) {
        LOG_ERROR("At least one DNS server is required");
        return false;
    }

    if (timeouts_.handshake == 0 || timeouts_.dial == 0) {
        LOG_ERROR("Timeout values must be positive");
        return false;
    }

    if (limits_.buffer_size < 1024) {
        LOG_ERROR("Buffer size must be at least 1KB");
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
