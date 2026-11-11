#include <gtest/gtest.h>

#include "common/rule.hpp"
#include "common/session.hpp"

#include <memory>
#include <regex>
#include <string_view>
#include <vector>

namespace {

::rule::DetectRulePolicy::RuleListPtr MakeRules(
    std::initializer_list<::rule::DetectRule> rules) {
    return std::make_shared<const ::rule::DetectRulePolicy::RuleList>(rules);
}

}  // namespace
class RuleLifecycle : public testing::Test {
protected:
    void SetUp() override {
        context.inbound.tag = tag;
        context.inbound.user_id = 42;
        context.inbound.user_email = "alice@example.com";
        context.outbound.target = ::TargetAddress("blocked.example", 443);
        policy.UpdateRule(tag, MakeRules({::rule::DetectRule{
            .Pattern = std::regex("blocked\\.example"),
        }}));
    }
    static constexpr std::string_view tag = "panel|vmess|443";
    ::rule::DetectRulePolicy policy;
    ::session::Context context;
};

TEST_F(RuleLifecycle, MatchesTargetOnlyForAuthenticatedInboundIdentity) {
    EXPECT_TRUE(policy.Blocked(context));
    context.outbound.target = ::TargetAddress("allowed.example", 443);
    EXPECT_FALSE(policy.Blocked(context));
    context.outbound.target = ::TargetAddress("blocked.example", 443);
    context.inbound.user_id = 0;
    EXPECT_FALSE(policy.Blocked(context));
    context.inbound.user_id = 42;
    context.inbound.tag = "another-node";
    EXPECT_FALSE(policy.Blocked(context));
}

TEST_F(RuleLifecycle, ReplacementAndRemovalTakeEffectWithoutRetainingOldRules) {
    EXPECT_TRUE(policy.Blocked(context));
    policy.UpdateRule(tag, MakeRules({::rule::DetectRule{
        .Pattern = std::regex("replacement\\.example"),
    }}));
    EXPECT_FALSE(policy.Blocked(context));
    context.outbound.target = ::TargetAddress("replacement.example", 443);
    EXPECT_TRUE(policy.Blocked(context));
    policy.UpdateRule(tag, {});
    EXPECT_FALSE(policy.Blocked(context));
}

TEST_F(RuleLifecycle, RouteOnlyAndOriginalTargetsCannotBypassBlocking) {
    context.outbound.target = ::TargetAddress("1.1.1.1", 443);
    context.outbound.route_target = ::TargetAddress("blocked.example", 443);
    EXPECT_TRUE(policy.Blocked(context));
    context.outbound.route_target = ::TargetAddress("allowed.example", 443);
    context.outbound.original_target = ::TargetAddress("blocked.example", 443);
    EXPECT_TRUE(policy.Blocked(context));
    context.outbound.original_target = {};
    EXPECT_FALSE(policy.Blocked(context));
}

TEST_F(RuleLifecycle, ResolvedAddressCannotBypassIpBlocking) {
    policy.UpdateRule(tag, MakeRules({::rule::DetectRule{
        .Pattern = std::regex("192\\.0\\.2\\.99"),
    }}));
    context.outbound.target = ::TargetAddress("allowed.example", 443);
    context.outbound.target.resolved_addr = ::net::ip::make_address("192.0.2.99");
    EXPECT_TRUE(policy.Blocked(context));
    context.outbound.target.resolved_addr = std::nullopt;
    EXPECT_FALSE(policy.Blocked(context));
}
