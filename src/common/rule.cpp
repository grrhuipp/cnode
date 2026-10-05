#include "acppnode/common/rule.hpp"

#include "acppnode/common/allocator.hpp"
#include "acppnode/common/string_hash.hpp"

#include <asio/strand.hpp>

#include <charconv>
#include <iterator>
#include <regex>
#include <string>

namespace acpp::rule {
namespace {

using RuleList = memory::DataVector<DetectRule>;
using DetectResultList = memory::DataVector<DetectResult>;
using InboundRule =
    memory::DataUnorderedMap<std::string,
                                    RuleList,
                                    TransparentStringHash,
                                    TransparentStringEq>;
using InboundDetectResult =
    memory::DataUnorderedMap<std::string,
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

[[nodiscard]] bool ContainsResult(const memory::DataVector<DetectResult>& results,
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
    Impl(net::any_io_executor executor, size_t channel_capacity)
        : channel(net::make_strand(std::move(executor)), channel_capacity) {}

    ServiceChannel channel;
    InboundRule rules;
    InboundDetectResult inbound_detect_result;
    [[nodiscard]] bool Detect(std::string_view tag,
                              std::string_view destination,
                              std::string_view email,
                              int64_t user_id);
};

Manager::Manager(net::any_io_executor executor, size_t channel_capacity)
    : impl_(std::make_unique<Impl>(std::move(executor), channel_capacity)) {}

Manager::~Manager() = default;

net::awaitable<void> Manager::UpdateRule(
    std::string tag,
    std::vector<DetectRule> new_rule_list) {
    co_await impl_->channel.Call([
        impl = impl_.get(), tag = std::move(tag), rules = std::move(new_rule_list)]() mutable {
        if (tag.empty()) return;
        if (rules.empty()) {
            impl->rules.erase(tag);
            impl->inbound_detect_result.erase(tag);
            return;
        }
        auto& destination = impl->rules[tag];
        destination.assign(rules.begin(), rules.end());
    });
}

net::awaitable<std::vector<DetectResult>>
Manager::GetDetectResult(std::string tag) {
    co_return co_await impl_->channel.Call(
        [impl = impl_.get(), tag = std::move(tag)]() mutable {
            std::vector<DetectResult> result;
            auto it = impl->inbound_detect_result.find(tag);
            if (it == impl->inbound_detect_result.end()) return result;
            result.assign(std::make_move_iterator(it->second.begin()),
                          std::make_move_iterator(it->second.end()));
            impl->inbound_detect_result.erase(it);
            return result;
        });
}

bool Manager::Impl::Detect(std::string_view tag,
                           std::string_view destination,
                           std::string_view email,
                           int64_t user_id) {
    auto rules_it = rules.find(tag);
    if (rules_it == rules.end()) {
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

    const auto uid = user_id > 0 ? std::optional<int64_t>{user_id}
                                 : ParseUidFromEmail(email);
    if (!uid) return true;

    auto& results = inbound_detect_result[std::string(tag)];
    if (!ContainsResult(results, *uid, hit_rule_id)) {
        results.push_back(DetectResult{.UID = *uid, .RuleID = hit_rule_id});
    }
    return true;
}

net::awaitable<bool> Manager::Blocked(
    std::string inbound_tag,
    int64_t user_id,
    std::string user_email,
    std::string destination) {
    if (user_id == 0) co_return false;
    co_return co_await impl_->channel.Call(
        [impl = impl_.get(), tag = std::move(inbound_tag), user_id,
         email = std::move(user_email), destination = std::move(destination)] {
            return impl->Detect(tag, destination, email, user_id);
        });
}

}  // namespace acpp::rule
