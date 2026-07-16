#pragma once

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
    std::vector<std::string> dest_override = {
        std::string(constants::protocol::kTls),
        std::string(constants::protocol::kHttp),
    };
    std::vector<std::string> domains_excluded;
    uint8_t dest_override_mask = kOverrideTls | kOverrideHttp;

    // 冷路径在配置进入 Worker 前刷新；请求期只做协议名 -> bit 判断。
    void RefreshHotPathFields() {
        dest_override_mask = 0;
        for (const auto& protocol : dest_override) {
            dest_override_mask |= OverrideBit(protocol);
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

    [[nodiscard]] bool IsDomainExcluded(std::string_view domain) const noexcept {
        for (const auto& excluded : domains_excluded) {
            if (excluded.size() != domain.size()) {
                continue;
            }

            bool equal = true;
            for (size_t i = 0; i < domain.size(); ++i) {
                if (ToLowerAscii(static_cast<unsigned char>(excluded[i])) !=
                    ToLowerAscii(static_cast<unsigned char>(domain[i]))) {
                    equal = false;
                    break;
                }
            }
            if (equal) {
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
        return result;
    }

private:
    static constexpr uint8_t kOverrideTls = 1u << 0;
    static constexpr uint8_t kOverrideHttp = 1u << 1;

    [[nodiscard]] static constexpr char ToLowerAscii(unsigned char ch) noexcept {
        return ch >= 'A' && ch <= 'Z'
            ? static_cast<char>(ch + ('a' - 'A'))
            : static_cast<char>(ch);
    }

    [[nodiscard]] static constexpr uint8_t OverrideBit(std::string_view protocol) noexcept {
        if (protocol == constants::protocol::kTls) {
            return kOverrideTls;
        }
        if (protocol == constants::protocol::kHttp) {
            return kOverrideHttp;
        }
        return 0;
    }
};

}  // namespace acpp
