#include "node_transition.hpp"

#include "acppnode/core/constants.hpp"

#include <string_view>

namespace acpp::controller {

namespace {

std::string_view EffectiveProtocol(const api::NodeInfo& node) noexcept {
    return node.NodeType.empty()
        ? std::string_view(constants::protocol::kDefaultNodeProtocol)
        : std::string_view(node.NodeType);
}

}  // namespace

bool NodeConfigChanged(const api::NodeInfo& current,
                       const api::NodeInfo& candidate) noexcept {
    return current.Port != candidate.Port
        || EffectiveProtocol(current) != EffectiveProtocol(candidate)
        || current.TransportProtocol != candidate.TransportProtocol
        || current.Path != candidate.Path
        || current.Host != candidate.Host
        || current.EnableTLS != candidate.EnableTLS
        || current.TLSServerName != candidate.TLSServerName
        || current.CypherMethod != candidate.CypherMethod
        || current.ShadowsocksServerKey != candidate.ShadowsocksServerKey
        || current.SniffEnabled != candidate.SniffEnabled
        || current.DestOverride != candidate.DestOverride;
}

NodeTransitionPlan PlanNodeTransition(const api::NodeInfo* current,
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
    if (EffectiveProtocol(*current) == EffectiveProtocol(candidate)) {
        return {NodeTransitionMode::ReplaceInPlace};
    }
    return {NodeTransitionMode::SwapSameEndpoint};
}

}  // namespace acpp::controller
