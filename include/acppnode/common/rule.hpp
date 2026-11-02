#pragma once

#include "acppnode/common/rule_types.hpp"
#include "acppnode/features/policy/request_policy.hpp"
#include "acppnode/common/allocator.hpp"

#include <memory>
#include <string_view>
#include <vector>

namespace acpp::rule {

// Owned by one Worker and accessed only on that Worker's io_context.
class Manager final : public features::policy::RequestPolicy, public memory::ThreadAllocated {
public:
    Manager();
    ~Manager();

    Manager(const Manager&) = delete;
    Manager& operator=(const Manager&) = delete;
    Manager(Manager&&) noexcept;
    Manager& operator=(Manager&&) noexcept;

    void UpdateRule(std::string_view tag, const std::vector<DetectRule>& new_rule_list);
    [[nodiscard]] bool Blocked(
        const session::Context& ctx) override;
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace acpp::rule
