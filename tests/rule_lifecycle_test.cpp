#include "acppnode/common/rule.hpp"
#include "acppnode/common/session.hpp"

#include <regex>
#include <string_view>
#include <vector>

int main() {
    acpp::rule::Manager manager;
    constexpr std::string_view tag = "panel|vmess|443";

    manager.UpdateRule(tag, {
        acpp::rule::DetectRule{
            .Pattern = std::regex("blocked\\.example"),
        },
    });

    acpp::session::Context ctx;
    ctx.inbound.tag = tag;
    ctx.inbound.user_id = 42;
    ctx.inbound.user_email = "alice@example.com";
    ctx.outbound.target = acpp::TargetAddress("blocked.example", 443);
    acpp::features::policy::RequestPolicy& policy = manager;
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

    manager.UpdateRule(tag, {
        acpp::rule::DetectRule{
            .Pattern = std::regex("replacement\\.example"),
        },
    });
    if (policy.Blocked(ctx)) return 7;
    ctx.outbound.target = acpp::TargetAddress("replacement.example", 443);
    if (!policy.Blocked(ctx)) return 8;
    manager.UpdateRule(tag, {});
    if (policy.Blocked(ctx)) return 10;
    return 0;
}
