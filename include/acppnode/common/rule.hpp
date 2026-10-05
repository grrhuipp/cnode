#pragma once

#include "acppnode/common/rule_types.hpp"
#include "acppnode/runtime/channel.hpp"
#include "acppnode/features/policy/request_policy.hpp"

#include <memory>
#include <string_view>
#include <vector>

namespace acpp::rule {

// XrayR common/rule.Manager counterpart.
// Mutable policy state is owned by its service strand.
class Manager final : public features::policy::RequestPolicy {
public:
    explicit Manager(net::any_io_executor executor,
                     size_t channel_capacity = 1024);
    ~Manager();

    Manager(const Manager&) = delete;
    Manager& operator=(const Manager&) = delete;
    Manager(Manager&&) = delete;
    Manager& operator=(Manager&&) = delete;

    net::awaitable<void> UpdateRule(std::string tag,
                                    std::vector<DetectRule> new_rule_list);
    [[nodiscard]] net::awaitable<std::vector<DetectResult>>
        GetDetectResult(std::string tag);
    [[nodiscard]] net::awaitable<bool> Blocked(
        std::string inbound_tag,
        int64_t user_id,
        std::string user_email,
        std::string destination) override;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace acpp::rule
