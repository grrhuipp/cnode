#pragma once

#include "api/api.hpp"

#include <chrono>
#include <cstdint>

namespace controller {

enum class NodeTransitionMode {
    Refresh,
    Create,
    Recover,
    StageNewEndpoint,
    ReplaceInPlace,
    SwapSameEndpoint,
};

struct NodeTransitionPlan {
    NodeTransitionMode mode = NodeTransitionMode::Refresh;

    [[nodiscard]] bool Transitioning() const noexcept {
        return mode != NodeTransitionMode::Refresh;
    }

    [[nodiscard]] bool DestructiveSwap() const noexcept {
        return mode == NodeTransitionMode::SwapSameEndpoint;
    }

    [[nodiscard]] bool RetireOldInboundBeforeCommit() const noexcept {
        return mode == NodeTransitionMode::StageNewEndpoint;
    }

};

[[nodiscard]] bool NodeConfigChanged(const api::NodeInfo& current,
                                     const api::NodeInfo& candidate) noexcept;

[[nodiscard]] NodeTransitionPlan PlanNodeTransition(
    const api::NodeInfo* current,
    bool current_started,
    const api::NodeInfo& candidate) noexcept;


[[nodiscard]] constexpr std::chrono::seconds PanelInterval(
    int configured_seconds,
    uint32_t fallback_seconds) noexcept {
    return std::chrono::seconds(
        configured_seconds > 0
            ? static_cast<uint32_t>(configured_seconds)
            : fallback_seconds);
}
}  // namespace controller
