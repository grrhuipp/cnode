#include "acppnode/common/rule.hpp"

#include "acppnode/common/ip_utils.hpp"
#include "acppnode/common/session.hpp"

#include <algorithm>
#include <charconv>
#include <cstring>
#include <optional>
#include <regex>

namespace acpp::rule {

DetectRulePolicy::DetectRulePolicy()
    : rules_(std::make_shared<const InboundRule>()) {}
DetectRulePolicy::~DetectRulePolicy() = default;

void DetectRulePolicy::UpdateRule(std::string_view tag,
                                  const std::vector<DetectRule>& new_rule_list) {
    if (tag.empty()) return;
    const std::lock_guard lock(update_mutex_);
    auto next = std::make_shared<InboundRule>(*rules_.load(std::memory_order_acquire));
    if (new_rule_list.empty()) {
        if (auto it = next->find(tag); it != next->end()) next->erase(it);
    } else {
        next->insert_or_assign(std::string(tag), new_rule_list);
    }
    rules_.store(std::move(next), std::memory_order_release);
}

bool DetectRulePolicy::Blocked(const session::Context& ctx) {
    if (ctx.inbound.user_id <= 0) {
        return false;
    }

    const auto rules = rules_.load(std::memory_order_acquire);
    const auto rules_it = rules->find(ctx.inbound.tag);
    if (rules_it == rules->end()) {
        return false;
    }

    const auto& target = ctx.outbound.target;
    std::optional<iputil::AddressText> addr_text;
    std::string_view host(target.host.data(), target.host.size());
    if (host.empty() && target.resolved_addr) {
        addr_text.emplace(*target.resolved_addr);
        host = addr_text->View();
    }

    char buf[280];
    char* out = buf;
    const bool bracket_ipv6 = iputil::NeedsIpv6Brackets(host);
    const std::size_t max_host_len = sizeof(buf) - (bracket_ipv6 ? 2 : 0) - 6;
    const std::size_t host_len = std::min(host.size(), max_host_len);
    if (bracket_ipv6) {
        *out++ = '[';
    }
    if (host_len > 0) {
        std::memcpy(out, host.data(), host_len);
        out += host_len;
    }
    if (bracket_ipv6) {
        *out++ = ']';
    }
    *out++ = ':';
    auto [end, ec] = std::to_chars(out, buf + sizeof(buf), target.port);
    (void)ec;

    for (const auto& rule : rules_it->second) {
        if (std::regex_search(buf, end, rule.Pattern)) {
            return true;
        }
    }
    return false;
}

}  // namespace acpp::rule
