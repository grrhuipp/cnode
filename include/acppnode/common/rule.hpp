#pragma once

#include "acppnode/common/rule_types.hpp"
#include "acppnode/features/policy/request_policy.hpp"

#include <memory>
#include <string_view>
#include <vector>

namespace acpp::rule {

// XrayR common/rule.Manager counterpart.
// Owned by one Worker and accessed only on that Worker's io_context.
class Manager final : public features::policy::RequestPolicy {
public:
    Manager();
    ~Manager();

    Manager(const Manager&) = delete;
    Manager& operator=(const Manager&) = delete;
    Manager(Manager&&) noexcept;
    Manager& operator=(Manager&&) noexcept;

    void UpdateRule(std::string_view tag, const std::vector<DetectRule>& new_rule_list);
    [[nodiscard]] bool HasRule(std::string_view tag) const noexcept;
    [[nodiscard]] std::vector<DetectResult> GetDetectResult(std::string_view tag);
    [[nodiscard]] bool Detect(std::string_view tag,
                              std::string_view destination,
                              std::string_view email);
    [[nodiscard]] bool Blocked(
        const session::Context& ctx) override;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace acpp::rule
