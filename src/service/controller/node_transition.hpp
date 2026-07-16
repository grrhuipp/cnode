#pragma once

#include "acppnode/api/api.hpp"

namespace acpp::controller {

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

    [[nodiscard]] bool RestoreOldInboundOnRollback() const noexcept {
        return mode == NodeTransitionMode::ReplaceInPlace
            || mode == NodeTransitionMode::SwapSameEndpoint;
    }
};

[[nodiscard]] bool NodeConfigChanged(const api::NodeInfo& current,
                                     const api::NodeInfo& candidate) noexcept;

[[nodiscard]] NodeTransitionPlan PlanNodeTransition(
    const api::NodeInfo* current,
    bool current_started,
    const api::NodeInfo& candidate) noexcept;

}  // namespace acpp::controller
