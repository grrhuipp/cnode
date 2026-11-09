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

[[nodiscard]] inline bool NodeConfigChanged(
    const api::NodeInfo& current,
    const api::NodeInfo& candidate) noexcept {
    return current.Port != candidate.Port
        || current.NodeType != candidate.NodeType
        || current.TransportProtocol != candidate.TransportProtocol
        || current.Path != candidate.Path
        || current.Host != candidate.Host
        || current.EnableTLS != candidate.EnableTLS
        || current.EnableReality != candidate.EnableReality
        || current.Flow != candidate.Flow
        || current.ServiceName != candidate.ServiceName
        || current.Reality != candidate.Reality
        || current.TLSServerName != candidate.TLSServerName
        || current.CypherMethod != candidate.CypherMethod
        || current.ShadowsocksServerKey != candidate.ShadowsocksServerKey
        || current.PaddingScheme != candidate.PaddingScheme
        || current.HysteriaUpMbps != candidate.HysteriaUpMbps
        || current.HysteriaDownMbps != candidate.HysteriaDownMbps;
}

[[nodiscard]] inline NodeTransitionPlan PlanNodeTransition(
    const api::NodeInfo* current,
    bool current_started,
    const api::NodeInfo& candidate) noexcept {
    if (current == nullptr) {
        return {NodeTransitionMode::Create};
    }
    if (!current_started) {
        return {NodeTransitionMode::Recover};
    }
    if (!NodeConfigChanged(*current, candidate)) {
        return {NodeTransitionMode::Refresh};
    }
    if (current->Port != candidate.Port) {
        return {NodeTransitionMode::StageNewEndpoint};
    }
    if (current->NodeType == candidate.NodeType) {
        return {NodeTransitionMode::ReplaceInPlace};
    }
    return {NodeTransitionMode::SwapSameEndpoint};
}

[[nodiscard]] constexpr std::chrono::seconds PanelInterval(
    int configured_seconds,
    uint32_t fallback_seconds) noexcept {
    return std::chrono::seconds(
        configured_seconds > 0
            ? static_cast<uint32_t>(configured_seconds)
            : fallback_seconds);
}
}  // namespace controller
