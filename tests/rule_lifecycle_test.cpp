#include "acppnode/common/rule.hpp"
#include "acppnode/common/session.hpp"

#include <regex>
#include <string_view>
#include <vector>

int main() {
    acpp::rule::DetectRulePolicy detect_rule_policy;
    constexpr std::string_view tag = "panel|vmess|443";

    detect_rule_policy.UpdateRule(tag, {
        acpp::rule::DetectRule{
            .Pattern = std::regex("blocked\\.example"),
        },
    });

    acpp::session::Context ctx;
    ctx.inbound.tag = tag;
    ctx.inbound.user_id = 42;
    ctx.inbound.user_email = "alice@example.com";
    ctx.outbound.target = acpp::TargetAddress("blocked.example", 443);
    acpp::features::policy::RequestPolicy& policy = detect_rule_policy;
    if (!policy.Blocked(ctx)) return 2;

    if (!policy.Blocked(ctx)) return 3;
    ctx.outbound.target = acpp::TargetAddress("allowed.example", 443);
    if (policy.Blocked(ctx)) return 4;
    ctx.outbound.target = acpp::TargetAddress("blocked.example", 443);
    ctx.inbound.user_id = 0;
    if (policy.Blocked(ctx)) return 5;
    ctx.inbound.user_id = 42;
    ctx.inbound.tag = "another-node";
    if (policy.Blocked(ctx)) return 6;
    ctx.inbound.tag = tag;

    detect_rule_policy.UpdateRule(tag, {
        acpp::rule::DetectRule{
            .Pattern = std::regex("replacement\\.example"),
        },
    });
    if (policy.Blocked(ctx)) return 7;
    ctx.outbound.target = acpp::TargetAddress("replacement.example", 443);
    if (!policy.Blocked(ctx)) return 8;
    detect_rule_policy.UpdateRule(tag, {});
    // Verify route_only (route_target) and original_target cannot bypass block rules.
    detect_rule_policy.UpdateRule(tag, {
        acpp::rule::DetectRule{
            .Pattern = std::regex("sniffed\\.blocked\\.example"),
        },
    });
    ctx.outbound.target = acpp::TargetAddress("1.1.1.1", 443);
    ctx.outbound.route_target = acpp::TargetAddress("sniffed.blocked.example", 443);
    if (!policy.Blocked(ctx)) return 11;
    ctx.outbound.route_target = acpp::TargetAddress("allowed.example", 443);
    ctx.outbound.original_target = acpp::TargetAddress("sniffed.blocked.example", 443);
    if (!policy.Blocked(ctx)) return 12;
    ctx.outbound.original_target = {};
    // A domain target whose resolved_addr matches an IP block rule must also be blocked.
    detect_rule_policy.UpdateRule(tag, {
        acpp::rule::DetectRule{
            .Pattern = std::regex("192\\.0\\.2\\.99"),
        },
    });
    ctx.outbound.target = acpp::TargetAddress("allowed.example", 443);
    ctx.outbound.target.resolved_addr = acpp::net::ip::make_address("192.0.2.99");
    if (!policy.Blocked(ctx)) return 13;
    ctx.outbound.target.resolved_addr = std::nullopt;
    detect_rule_policy.UpdateRule(tag, {});
    if (policy.Blocked(ctx)) return 10;
    return 0;
}
