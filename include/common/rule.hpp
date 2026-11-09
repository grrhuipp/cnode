#pragma once

#include "common/rule_types.hpp"
#include "features/policy/request_policy.hpp"
#include "common/allocator.hpp"
#include "common/string_hash.hpp"

#include <memory>
#include <string_view>
#include <vector>

namespace rule {

class DetectRulePolicy final : public features::policy::RequestPolicy {
public:
    using RuleList = std::vector<DetectRule>;
    using RuleListPtr = std::shared_ptr<const RuleList>;
    using InboundRule = memory::ThreadLocalUnorderedMap<
        memory::ThreadLocalString,
        RuleListPtr,
        TransparentStringHash,
        TransparentStringEq>;

    DetectRulePolicy();
    ~DetectRulePolicy();

    DetectRulePolicy(const DetectRulePolicy&) = delete;
    DetectRulePolicy& operator=(const DetectRulePolicy&) = delete;
    DetectRulePolicy(DetectRulePolicy&&) = delete;
    DetectRulePolicy& operator=(DetectRulePolicy&&) = delete;

    void UpdateRule(std::string_view tag, std::vector<DetectRule> new_rule_list);
    void UpdateSharedRule(std::string_view tag, RuleListPtr new_rule_list);
    [[nodiscard]] bool Blocked(
        const session::Context& ctx) override;
private:
    InboundRule rules_;
};

}  // namespace rule
