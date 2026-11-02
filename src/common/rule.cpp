#include "acppnode/common/rule.hpp"

#include "acppnode/common/allocator.hpp"
#include "acppnode/common/session.hpp"
#include "acppnode/common/string_hash.hpp"

#include <regex>
#include <string>

namespace acpp::rule {
namespace {

using RuleList = memory::ThreadLocalVector<DetectRule>;
using InboundRule =
    memory::ThreadLocalUnorderedMap<memory::ThreadLocalString,
                                    RuleList,
                                    TransparentStringHash,
                                    TransparentStringEq>;
}  // namespace

struct Manager::Impl {
    InboundRule rules;
};

Manager::Manager()
    : impl_(std::make_unique<Impl>()) {
}

Manager::~Manager() = default;
Manager::Manager(Manager&&) noexcept = default;
Manager& Manager::operator=(Manager&&) noexcept = default;

void Manager::UpdateRule(std::string_view tag,
                         const std::vector<DetectRule>& new_rule_list) {
    if (tag.empty()) {
        return;
    }

    if (new_rule_list.empty()) {
        if (auto it = impl_->rules.find(tag); it != impl_->rules.end()) {
            impl_->rules.erase(it);
        }
        return;
    }

    auto it = impl_->rules.find(tag);
    if (it == impl_->rules.end()) {
        it = impl_->rules.try_emplace(memory::ThreadLocalString(tag)).first;
    }
    auto& rules = it->second;
    rules.clear();
    rules.reserve(new_rule_list.size());
    for (const auto& rule : new_rule_list) {
        rules.push_back(rule);
    }
}

bool Manager::HasRule(std::string_view tag) const noexcept {
    return impl_->rules.find(tag) != impl_->rules.end();
}

bool Manager::Blocked(const session::Context& ctx) {
    if (ctx.inbound.user_id <= 0) {
        return false;
    }

    const auto rules_it = impl_->rules.find(ctx.inbound.tag);
    if (rules_it == impl_->rules.end()) {
        return false;
    }

    // Worker-local scratch avoids a per-request destination string allocation.
    thread_local std::string destination;
    ctx.outbound.target.ToStringInto(destination);

    int hit_rule_id = -1;
    for (const auto& rule : rules_it->second) {
        if (std::regex_search(destination.begin(), destination.end(), rule.Pattern)) {
            hit_rule_id = rule.ID;
            break;
        }
    }

    if (hit_rule_id < 0) {
        return false;
    }

    return true;
}

}  // namespace acpp::rule
