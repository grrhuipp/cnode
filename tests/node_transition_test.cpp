#include <gtest/gtest.h>

#include "node_transition.hpp"

namespace {

using ::api::NodeInfo;
using ::controller::NodeTransitionMode;

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
    const auto plan = ::controller::PlanNodeTransition(
        current, current_started, candidate);
    return plan.mode == mode
        && plan.Transitioning() == (mode != NodeTransitionMode::Refresh)
        && plan.DestructiveSwap() == (mode == NodeTransitionMode::SwapSameEndpoint)
        && plan.RetireOldInboundBeforeCommit()
            == (mode == NodeTransitionMode::StageNewEndpoint);
}

}  // namespace

TEST(NodeTransition, Contract) {
    const NodeInfo current = MakeNode();

    ASSERT_FALSE((!HasMode(nullptr, false, current, NodeTransitionMode::Create)
        || !HasMode(&current, false, current, NodeTransitionMode::Recover)
        || !HasMode(&current, true, current, NodeTransitionMode::Refresh)));

    NodeInfo different_port = current;
    different_port.Port = 8443;
    ASSERT_FALSE((!HasMode(&current, true, different_port,
                 NodeTransitionMode::StageNewEndpoint)));

    NodeInfo same_port_changed = current;
    same_port_changed.EnableTLS = true;
    ASSERT_FALSE((!HasMode(&current, true, same_port_changed,
                 NodeTransitionMode::ReplaceInPlace)));

    NodeInfo same_port_new_protocol = current;
    same_port_new_protocol.NodeType = "shadowsocks";
    ASSERT_FALSE((!HasMode(&current, true, same_port_new_protocol,
                 NodeTransitionMode::SwapSameEndpoint)));

    NodeInfo changed = current;
    changed.TransportProtocol = "ws";
    ASSERT_FALSE((!::controller::NodeConfigChanged(current, changed)));
    changed = current;
    changed.Path = "/proxy";
    ASSERT_FALSE((!::controller::NodeConfigChanged(current, changed)));
    changed = current;
    changed.NodeType = "shadowsocks";
    ASSERT_FALSE((!::controller::NodeConfigChanged(current, changed)));
    changed = current;
    changed.Sniffing.enabled = !current.Sniffing.enabled;
    ASSERT_FALSE((!::controller::NodeConfigChanged(current, changed)));
    changed = current;
    changed.Sniffing.dest_override = ::SniffConfig::kHttp;
    ASSERT_FALSE((!::controller::NodeConfigChanged(current, changed)));

    changed = current;
    changed.PullInterval = current.PullInterval + 1;
    changed.PushInterval = current.PushInterval + 2;
    ASSERT_FALSE((::controller::NodeConfigChanged(current, changed)));

}
