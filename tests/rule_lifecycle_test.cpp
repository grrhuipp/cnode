#include <gtest/gtest.h>

#include "common/rule.hpp"
#include "common/session.hpp"

#include <regex>
#include <string_view>
#include <vector>

TEST(RuleLifecycle, Contract) {
    ::rule::DetectRulePolicy detect_rule_policy;
    constexpr std::string_view tag = "panel|vmess|443";

    detect_rule_policy.UpdateRule(tag, {
        ::rule::DetectRule{
            .Pattern = std::regex("blocked\\.example"),
        },
    });

    ::session::Context ctx;
    ctx.inbound.tag = tag;
    ctx.inbound.user_id = 42;
    ctx.inbound.user_email = "alice@example.com";
    ctx.outbound.target = ::TargetAddress("blocked.example", 443);
    ::features::policy::RequestPolicy& policy = detect_rule_policy;
    ASSERT_FALSE((!policy.Blocked(ctx)));

    ASSERT_FALSE((!policy.Blocked(ctx)));
    ctx.outbound.target = ::TargetAddress("allowed.example", 443);
    ASSERT_FALSE((policy.Blocked(ctx)));
    ctx.outbound.target = ::TargetAddress("blocked.example", 443);
    ctx.inbound.user_id = 0;
    ASSERT_FALSE((policy.Blocked(ctx)));
    ctx.inbound.user_id = 42;
    ctx.inbound.tag = "another-node";
    ASSERT_FALSE((policy.Blocked(ctx)));
    ctx.inbound.tag = tag;

    detect_rule_policy.UpdateRule(tag, {
        ::rule::DetectRule{
            .Pattern = std::regex("replacement\\.example"),
        },
    });
    ASSERT_FALSE((policy.Blocked(ctx)));
    ctx.outbound.target = ::TargetAddress("replacement.example", 443);
    ASSERT_FALSE((!policy.Blocked(ctx)));
    detect_rule_policy.UpdateRule(tag, {});
    // Verify route_only (route_target) and original_target cannot bypass block rules.
    detect_rule_policy.UpdateRule(tag, {
        ::rule::DetectRule{
            .Pattern = std::regex("sniffed\\.blocked\\.example"),
        },
    });
    ctx.outbound.target = ::TargetAddress("1.1.1.1", 443);
    ctx.outbound.route_target = ::TargetAddress("sniffed.blocked.example", 443);
    ASSERT_FALSE((!policy.Blocked(ctx)));
    ctx.outbound.route_target = ::TargetAddress("allowed.example", 443);
    ctx.outbound.original_target = ::TargetAddress("sniffed.blocked.example", 443);
    ASSERT_FALSE((!policy.Blocked(ctx)));
    ctx.outbound.original_target = {};
    // A domain target whose resolved_addr matches an IP block rule must also be blocked.
    detect_rule_policy.UpdateRule(tag, {
        ::rule::DetectRule{
            .Pattern = std::regex("192\\.0\\.2\\.99"),
        },
    });
    ctx.outbound.target = ::TargetAddress("allowed.example", 443);
    ctx.outbound.target.resolved_addr = ::net::ip::make_address("192.0.2.99");
    ASSERT_FALSE((!policy.Blocked(ctx)));
    ctx.outbound.target.resolved_addr = std::nullopt;
    detect_rule_policy.UpdateRule(tag, {});
    ASSERT_FALSE((policy.Blocked(ctx)));
}
