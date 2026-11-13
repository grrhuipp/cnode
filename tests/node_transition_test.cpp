#include <gtest/gtest.h>

#include "controller/node_transaction.hpp"
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

struct TransitionCase {
    const char* name;
    bool exists;
    bool started;
    int change;
    NodeTransitionMode mode;
};
class NodeTransition : public ::testing::TestWithParam<TransitionCase> {};
TEST_P(NodeTransition, PlansRequiredLifecycleActions) {
    const auto& scenario = GetParam();
    const auto current = MakeNode();
    auto candidate = current;
    switch (scenario.change) {
    case 1: candidate.Port = 8443; break;
    case 2: candidate.EnableTLS = true; break;
    case 3: candidate.NodeType = "shadowsocks"; break;
    }
    const auto plan = ::controller::PlanNodeTransition(
        scenario.exists ? &current : nullptr, scenario.started, candidate);
    EXPECT_EQ(plan.mode, scenario.mode);
    EXPECT_EQ(plan.Transitioning(), scenario.mode != NodeTransitionMode::Refresh);
    EXPECT_EQ(plan.DestructiveSwap(), scenario.mode == NodeTransitionMode::SwapSameEndpoint);
    EXPECT_EQ(plan.RetireOldInboundBeforeCommit(), scenario.mode == NodeTransitionMode::StageNewEndpoint);
}
INSTANTIATE_TEST_SUITE_P(Lifecycle, NodeTransition, ::testing::Values(
    TransitionCase{"Create", false, false, 0, NodeTransitionMode::Create},
    TransitionCase{"Recover", true, false, 0, NodeTransitionMode::Recover},
    TransitionCase{"Refresh", true, true, 0, NodeTransitionMode::Refresh},
    TransitionCase{"StageNewEndpoint", true, true, 1, NodeTransitionMode::StageNewEndpoint},
    TransitionCase{"ReplaceInPlace", true, true, 2, NodeTransitionMode::ReplaceInPlace},
    TransitionCase{"SwapSameEndpoint", true, true, 3, NodeTransitionMode::SwapSameEndpoint}),
    [](const ::testing::TestParamInfo<TransitionCase>& info) { return info.param.name; });

TEST(NodeConfigChanged, DetectsTransportPathAndProtocolChanges) {
    const auto current = MakeNode();
    auto changed = current;
    changed.TransportProtocol = "ws";
    EXPECT_TRUE(::controller::NodeConfigChanged(current, changed));
    changed = current;
    changed.Path = "/proxy";
    EXPECT_TRUE(::controller::NodeConfigChanged(current, changed));
    changed = current;
    changed.NodeType = "shadowsocks";
    EXPECT_TRUE(::controller::NodeConfigChanged(current, changed));
}

TEST(NodeConfigChanged, ScheduleOnlyChangesDoNotReplaceInbound) {
    const auto current = MakeNode();
    auto changed = current;
    changed.PullInterval = current.PullInterval + 1;
    changed.PushInterval = current.PushInterval + 2;
    EXPECT_FALSE(::controller::NodeConfigChanged(current, changed));
}
}  // namespace
