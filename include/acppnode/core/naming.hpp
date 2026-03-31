#pragma once

#include "acppnode/core/constants.hpp"

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

}  // namespace acpp::naming
