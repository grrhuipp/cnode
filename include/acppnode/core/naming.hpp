#pragma once

#include "acppnode/core/constants.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <format>
#include <string>
#include <string_view>

namespace acpp::naming {

[[nodiscard]] inline std::string BuildProtocolPortTag(std::string_view protocol, uint16_t port) {
    return std::format("{}-{}", protocol, port);
}

[[nodiscard]] inline std::string BuildPanelNodeTag(std::string_view panel_name,
                                                   std::string_view protocol,
                                                   uint16_t port) {
    return std::format("{}-{}-{}", panel_name, protocol, port);
}

[[nodiscard]] inline std::string BuildPanelNodeStatsKey(std::string_view panel_name, int node_id) {
    return std::format("{}-{}", panel_name, node_id);
}

[[nodiscard]] inline std::string ResolveProtocolOrDefault(
    std::string_view protocol,
    std::string_view fallback = constants::protocol::kDefaultNodeProtocol) {
    return protocol.empty() ? std::string(fallback) : std::string(protocol);
}

[[nodiscard]] inline std::string LowerAscii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return value;
}

[[nodiscard]] inline std::string NormalizePanelNodeProtocol(std::string_view node_type) {
    const auto lowered = LowerAscii(std::string(node_type));
    if (lowered.empty() || lowered == "v2ray" || lowered == "vmess") {
        return std::string(constants::protocol::kVmess);
    }
    if (lowered == "vless") {
        return std::string(constants::protocol::kVless);
    }
    if (lowered == "trojan") {
        return std::string(constants::protocol::kTrojan);
    }
    if (lowered == "shadowsocks" || lowered == "shadowsocks-plugin" || lowered == "ss") {
        return std::string(constants::protocol::kShadowsocks);
    }
    if (lowered == "anytls") {
        return std::string(constants::protocol::kAnyTLS);
    }
    return std::string(node_type);
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

}  // namespace acpp::naming
