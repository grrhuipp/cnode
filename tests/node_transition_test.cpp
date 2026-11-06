#include "node_transition.hpp"

namespace {

using acpp::api::NodeInfo;
using acpp::controller::NodeTransitionMode;

NodeInfo MakeNode() {
    NodeInfo node;
    node.NodeType = "trojan";
    node.Port = 443;
    node.TransportProtocol = "tcp";
    node.Host = "example.test";
    return node;
}

bool HasMode(const NodeInfo* current,
             bool current_started,
             const NodeInfo& candidate,
             NodeTransitionMode mode) {
    const auto plan = acpp::controller::PlanNodeTransition(
        current, current_started, candidate);
    return plan.mode == mode
        && plan.Transitioning() == (mode != NodeTransitionMode::Refresh)
        && plan.DestructiveSwap() == (mode == NodeTransitionMode::SwapSameEndpoint)
        && plan.RetireOldInboundBeforeCommit()
            == (mode == NodeTransitionMode::StageNewEndpoint);
}

}  // namespace

int main() {
    const NodeInfo current = MakeNode();

    if (!HasMode(nullptr, false, current, NodeTransitionMode::Create)
        || !HasMode(&current, false, current, NodeTransitionMode::Recover)
        || !HasMode(&current, true, current, NodeTransitionMode::Refresh)) {
        return 1;
    }

    NodeInfo different_port = current;
    different_port.Port = 8443;
    if (!HasMode(&current, true, different_port,
                 NodeTransitionMode::StageNewEndpoint)) {
        return 2;
    }

    NodeInfo same_port_changed = current;
    same_port_changed.EnableTLS = true;
    if (!HasMode(&current, true, same_port_changed,
                 NodeTransitionMode::ReplaceInPlace)) {
        return 3;
    }

    NodeInfo same_port_new_protocol = current;
    same_port_new_protocol.NodeType = "shadowsocks";
    if (!HasMode(&current, true, same_port_new_protocol,
                 NodeTransitionMode::SwapSameEndpoint)) {
        return 4;
    }

    NodeInfo changed = current;
    changed.TransportProtocol = "ws";
    if (!acpp::controller::NodeConfigChanged(current, changed)) return 6;
    changed = current;
    changed.Path = "/proxy";
    if (!acpp::controller::NodeConfigChanged(current, changed)) return 7;
    changed = current;
    changed.NodeType = "shadowsocks";
    if (!acpp::controller::NodeConfigChanged(current, changed)) return 8;
    changed = current;
    changed.Sniffing.enabled = !current.Sniffing.enabled;
    if (!acpp::controller::NodeConfigChanged(current, changed)) return 9;
    changed = current;
    changed.Sniffing.dest_override = acpp::SniffConfig::kHttp;
    if (!acpp::controller::NodeConfigChanged(current, changed)) return 10;

    changed = current;
    changed.PullInterval = current.PullInterval + 1;
    changed.PushInterval = current.PushInterval + 2;
    if (acpp::controller::NodeConfigChanged(current, changed)) return 11;

    return 0;
}
