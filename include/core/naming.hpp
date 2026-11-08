#pragma once

#include "core/constants.hpp"

#include <algorithm>
#include <cstdint>
#include <format>
#include <string>
#include <string_view>

namespace naming {

inline constexpr std::string_view kPanelNodeTagPrefix = "panel/";

[[nodiscard]] inline std::string BuildProtocolPortTag(std::string_view protocol, uint16_t port) {
    return std::format("{}-{}", protocol, port);
}

[[nodiscard]] inline std::string BuildPanelNodeTag(std::string_view panel_name,
                                                   int node_id,
                                                   std::string_view protocol,
                                                   uint16_t port) {
    return std::format("{}{}/{}/{}/{}", kPanelNodeTagPrefix,
                       panel_name, node_id, protocol, port);
}

[[nodiscard]] inline std::string BuildPanelNodeAccountingKey(std::string_view panel_name,
                                                             int node_id) {
    return std::format("{}{}/{}/", kPanelNodeTagPrefix, panel_name, node_id);
}

[[nodiscard]] inline std::string LowerAscii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](char ch) {
        return ch >= 'A' && ch <= 'Z' ? static_cast<char>(ch - 'A' + 'a') : ch;
    });
    return value;
}

[[nodiscard]] inline std::string NormalizeV2BoardApiNodeType(std::string_view node_type) {
    const auto lowered = LowerAscii(std::string(node_type));
    if (lowered.empty() || lowered == "vmess") {
        return "v2ray";
    }
    if (lowered == "vless") {
        return "vless";
    }
    return lowered;
}

}  // namespace naming
