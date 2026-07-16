#include "acppnode/common/rule.hpp"

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
    if (!manager.Detect(tag, "blocked.example:443", "node|user|42")) return 2;

    manager.UpdateRule(tag, {});
    if (manager.HasRule(tag)) return 3;
    if (manager.Detect(tag, "blocked.example:443", "node|user|42")) return 4;
    if (!manager.GetDetectResult(tag).empty()) return 5;
    return 0;
}
