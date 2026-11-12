#pragma once

#include "common/string_hash.hpp"

#include <memory>
#include <regex>
#include <string_view>
#include <vector>
#include <string>
#include <unordered_map>

namespace session {
struct Context;
}  // namespace session

namespace rule {

struct DetectRule {
    std::regex Pattern;
};

class DetectRulePolicy final {
public:
    using RuleList = std::vector<DetectRule>;
    using RuleListPtr = std::shared_ptr<const RuleList>;
    using InboundRule = std::unordered_map<
        std::string,
        RuleListPtr,
        common::TransparentStringHash,
        common::TransparentStringEq>;

    DetectRulePolicy();
    ~DetectRulePolicy();

    DetectRulePolicy(const DetectRulePolicy&) = delete;
    DetectRulePolicy& operator=(const DetectRulePolicy&) = delete;
    DetectRulePolicy(DetectRulePolicy&&) = delete;
    DetectRulePolicy& operator=(DetectRulePolicy&&) = delete;

    void UpdateRule(std::string_view tag, RuleListPtr new_rule_list);
    [[nodiscard]] bool Blocked(
        const session::Context& ctx);
private:
    InboundRule rules_;
};

}  // namespace rule
