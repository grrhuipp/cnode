#include "node_transition.hpp"

namespace acpp::controller {

bool NodeConfigChanged(const api::NodeInfo& current,
                       const api::NodeInfo& candidate) noexcept {
    return current.Port != candidate.Port
        || current.NodeType != candidate.NodeType
        || current.TransportProtocol != candidate.TransportProtocol
        || current.Path != candidate.Path
        || current.Host != candidate.Host
        || current.EnableTLS != candidate.EnableTLS
        || current.TLSServerName != candidate.TLSServerName
        || current.TLSCert != candidate.TLSCert
        || current.TLSKey != candidate.TLSKey
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
    return {NodeTransitionMode::SwapSameEndpoint};
}

}  // namespace acpp::controller
