#pragma once

#include "common/rule_types.hpp"
#include "features/policy/request_policy.hpp"
#include "common/allocator.hpp"
#include "common/string_hash.hpp"

#include <string_view>
#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace rule {

// Process-owned cold publication endpoint. Requests read immutable snapshots;
// neither rules nor their allocation lifetime depend on the accepting Worker.
class DetectRulePolicy final : public features::policy::RequestPolicy {
public:
    using RuleList = std::vector<DetectRule>;
    using RuleListPtr = std::shared_ptr<const RuleList>;
    using InboundRule = std::unordered_map<std::string, RuleListPtr,
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
    std::mutex update_mutex_;
    std::shared_ptr<const InboundRule> rules_;
    std::atomic<uint64_t> generation_{1};
    std::atomic<bool> has_rules_{false};
};

}  // namespace rule
