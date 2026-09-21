#pragma once

#include "acppnode/common/domain_name.hpp"
#include "acppnode/core/constants.hpp"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace acpp {

// ============================================================================
// SniffConfig - 流量嗅探配置（所有协议共用）
// ============================================================================
struct SniffConfig {
    bool enabled = true;
    bool metadata_only = false;
    bool route_only = false;
    std::vector<std::string> dest_override = {
        std::string(constants::protocol::kTls),
        std::string(constants::protocol::kHttp),
        std::string(constants::protocol::kQuic),
    };
    std::vector<std::string> domains_excluded;
    uint8_t dest_override_mask = kOverrideTls | kOverrideHttp | kOverrideQuic;

    // 冷路径在配置进入 Worker 前刷新；请求期只做协议名 -> bit 判断。
    void RefreshHotPathFields() {
        dest_override_mask = 0;
        for (const auto& protocol : dest_override) {
            dest_override_mask |= OverrideBit(protocol);
        }
        for (auto& excluded : domains_excluded) {
            domain::NormalizeDnsHostnameInPlace(excluded);
        }
    }

    [[nodiscard]] bool MatchesDestOverride(std::string_view protocol) const {
        const uint8_t bit = OverrideBit(protocol);
        if (bit != 0) {
            return (dest_override_mask & bit) != 0;
        }

        for (const auto& candidate : dest_override) {
            if (candidate == protocol) {
                return true;
            }
        }
        return false;
    }

    [[nodiscard]] bool IsDomainExcluded(std::string_view hostname) const noexcept {
        for (const auto& excluded : domains_excluded) {
            if (domain::DnsHostnamesEqual(excluded, hostname)) {
                return true;
            }
        }
        return false;
    }

    std::string ToString() const {
        if (!enabled) return "disabled";
        std::string result = "enabled";
        if (!dest_override.empty()) {
            result += " override=[";
            for (size_t i = 0; i < dest_override.size(); ++i) {
                if (i > 0) result += ",";
                result += dest_override[i];
            }
            result += "]";
        }
        if (!domains_excluded.empty()) {
            result += " excluded=" + std::to_string(domains_excluded.size()) + " domains";
        }
        if (metadata_only) result += " metadataOnly";
        if (route_only) result += " routeOnly";
        return result;
    }

private:
    static constexpr uint8_t kOverrideTls = 1u << 0;
    static constexpr uint8_t kOverrideHttp = 1u << 1;
    static constexpr uint8_t kOverrideQuic = 1u << 2;
    static constexpr uint8_t kOverrideBitTorrent = 1u << 3;

    [[nodiscard]] static constexpr uint8_t OverrideBit(std::string_view protocol) noexcept {
        if (protocol == constants::protocol::kTls) {
            return kOverrideTls;
        }
        if (protocol == constants::protocol::kHttp) {
            return kOverrideHttp;
        }
        if (protocol == constants::protocol::kQuic) {
            return kOverrideQuic;
        }
        if (protocol == constants::protocol::kBitTorrent) {
            return kOverrideBitTorrent;
        }
        return 0;
    }
};

}  // namespace acpp
