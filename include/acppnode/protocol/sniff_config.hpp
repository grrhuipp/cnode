#pragma once

#include "acppnode/core/constants.hpp"

#include <string>
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
};

}  // namespace acpp
