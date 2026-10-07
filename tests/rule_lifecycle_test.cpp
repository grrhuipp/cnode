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
            .ID = 7,
            .Pattern = std::regex("blocked\\.example"),
        },
    });
    if (!manager.HasRule(tag)) return 1;

    acpp::session::Context ctx;
    ctx.inbound.tag = tag;
    ctx.inbound.user_id = 42;
    ctx.inbound.user_email = "node|user|42";
    ctx.outbound.target = acpp::TargetAddress("blocked.example", 443);
    acpp::features::policy::RequestPolicy& policy = manager;
    if (!policy.Blocked(ctx)) return 2;

    const auto results = manager.GetDetectResult(tag);
    if (results.size() != 1 || results.front().UID != 42 ||
        results.front().RuleID != 7) return 3;

    manager.UpdateRule(tag, {});
    if (manager.HasRule(tag)) return 4;
    if (policy.Blocked(ctx)) return 5;
    if (!manager.GetDetectResult(tag).empty()) return 6;
    return 0;
}
