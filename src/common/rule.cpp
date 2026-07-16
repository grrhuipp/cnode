#include "acppnode/common/rule.hpp"

#include "acppnode/common/allocator.hpp"
#include "acppnode/common/string_hash.hpp"

#include <charconv>
#include <iterator>
#include <regex>
#include <string>

namespace acpp::rule {
namespace {

using RuleList = memory::ThreadLocalVector<DetectRule>;
using DetectResultList = memory::ThreadLocalVector<DetectResult>;
using InboundRule =
    memory::ThreadLocalUnorderedMap<std::string,
                                    RuleList,
                                    TransparentStringHash,
                                    TransparentStringEq>;
using InboundDetectResult =
    memory::ThreadLocalUnorderedMap<std::string,
                                    DetectResultList,
                                    TransparentStringHash,
                                    TransparentStringEq>;

[[nodiscard]] std::optional<int64_t> ParseUidFromEmail(std::string_view email) {
    const size_t pos = email.rfind('|');
    if (pos == std::string_view::npos || pos + 1 >= email.size()) {
        return std::nullopt;
    }

    int64_t uid = 0;
    const char* first = email.data() + pos + 1;
    const char* last = email.data() + email.size();
    const auto [ptr, ec] = std::from_chars(first, last, uid);
    if (ec != std::errc{} || ptr != last) {
        return std::nullopt;
    }
    return uid;
}

[[nodiscard]] bool ContainsResult(const memory::ThreadLocalVector<DetectResult>& results,
                                  int64_t uid,
                                  int rule_id) noexcept {
    for (const auto& result : results) {
        if (result.UID == uid && result.RuleID == rule_id) {
            return true;
        }
    }
    return false;
}

}  // namespace

struct Manager::Impl {
    std::shared_ptr<const InboundRule> rules_snapshot =
        std::make_shared<const InboundRule>();
    InboundDetectResult inbound_detect_result;
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

    auto next_snapshot = std::make_shared<InboundRule>(*impl_->rules_snapshot);

    if (new_rule_list.empty()) {
        next_snapshot->erase(std::string(tag));
        impl_->rules_snapshot = std::move(next_snapshot);
        impl_->inbound_detect_result.erase(std::string(tag));
        return;
    }

    auto& rules = (*next_snapshot)[std::string(tag)];
    rules.clear();
    rules.reserve(new_rule_list.size());
    for (const auto& rule : new_rule_list) {
        rules.push_back(rule);
    }
    impl_->rules_snapshot = std::move(next_snapshot);
}

bool Manager::HasRule(std::string_view tag) const noexcept {
    const auto snapshot = impl_->rules_snapshot;
    return snapshot && snapshot->find(tag) != snapshot->end();
}

std::vector<DetectResult> Manager::GetDetectResult(std::string_view tag) {
    std::vector<DetectResult> result;
    auto it = impl_->inbound_detect_result.find(tag);
    if (it == impl_->inbound_detect_result.end()) {
        return result;
    }

    result.assign(std::make_move_iterator(it->second.begin()),
                  std::make_move_iterator(it->second.end()));
    impl_->inbound_detect_result.erase(it);
    return result;
}

bool Manager::Detect(std::string_view tag,
                     std::string_view destination,
                     std::string_view email) {
    const auto snapshot = impl_->rules_snapshot;
    if (!snapshot) {
        return false;
    }

    auto rules_it = snapshot->find(tag);
    if (rules_it == snapshot->end()) {
        return false;
    }

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

    const auto uid = ParseUidFromEmail(email);
    if (!uid) {
        return true;
    }

    auto& results = impl_->inbound_detect_result[std::string(tag)];
    if (!ContainsResult(results, *uid, hit_rule_id)) {
        results.push_back(DetectResult{
            .UID = *uid,
            .RuleID = hit_rule_id,
        });
    }
    return true;
}

}  // namespace acpp::rule
