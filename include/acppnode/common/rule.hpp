#pragma once

#include "acppnode/common/rule_types.hpp"
#include "acppnode/features/policy/request_policy.hpp"
#include "acppnode/common/allocator.hpp"
#include "acppnode/common/string_hash.hpp"

#include <string_view>
#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace acpp::rule {

// Process-owned cold publication endpoint. Requests read immutable snapshots;
// neither rules nor their allocation lifetime depend on the accepting Worker.
class DetectRulePolicy final : public features::policy::RequestPolicy {
public:
    DetectRulePolicy();
    ~DetectRulePolicy();

    DetectRulePolicy(const DetectRulePolicy&) = delete;
    DetectRulePolicy& operator=(const DetectRulePolicy&) = delete;
    DetectRulePolicy(DetectRulePolicy&&) = delete;
    DetectRulePolicy& operator=(DetectRulePolicy&&) = delete;

    void UpdateRule(std::string_view tag, std::vector<DetectRule> new_rule_list);
    [[nodiscard]] bool Blocked(
        const session::Context& ctx) override;
private:
    using RuleList = std::vector<DetectRule>;
    using InboundRule = std::unordered_map<std::string, RuleList,
                                          TransparentStringHash,
                                          TransparentStringEq>;
    std::mutex update_mutex_;
    std::atomic<std::shared_ptr<const InboundRule>> rules_;
};

}  // namespace acpp::rule
