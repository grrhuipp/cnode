#include "common/rule.hpp"

#include "common/ip_utils.hpp"
#include "common/session.hpp"

#include <algorithm>
#include <charconv>
#include <cstring>
#include <optional>
#include <regex>
#include <string>

namespace rule {

DetectRulePolicy::DetectRulePolicy() = default;
DetectRulePolicy::~DetectRulePolicy() = default;

void DetectRulePolicy::UpdateRule(std::string_view tag,
                                  RuleListPtr new_rule_list) {
    if (tag.empty()) return;
    const auto it = rules_.find(tag);
    if (!new_rule_list || new_rule_list->empty()) {
        if (it != rules_.end()) {
            rules_.erase(it);
        }
        return;
    }
    if (it != rules_.end()) {
        it->second = std::move(new_rule_list);
        return;
    }
    rules_.emplace(std::string(tag), std::move(new_rule_list));
}

bool DetectRulePolicy::Blocked(const session::Context& ctx) {
    if (ctx.inbound.user_id <= 0 || rules_.empty()) {
        return false;
    }
    const auto rules_it = rules_.find(ctx.inbound.tag);
    if (rules_it == rules_.end() || !rules_it->second || rules_it->second->empty()) {
        return false;
    }
    const auto& rule_list = *rules_it->second;

    auto matches_host_port = [&](std::string_view host, uint16_t port) {
        if (host.empty()) {
            return false;
        }

        char buf[280];
        char* out = buf;
        const bool bracket_ipv6 = iputil::NeedsIpv6Brackets(host);
        const std::size_t max_host_len = sizeof(buf) - (bracket_ipv6 ? 2 : 0) - 6;
        // 合法目标受 DNS/IP 长度边界约束；未来扩展若超出预算，也不能匹配截断后的目标。
        if (host.size() > max_host_len) return true;
        const std::size_t host_len = host.size();
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
        auto [end, ec] = std::to_chars(out, buf + sizeof(buf), port);
        (void)ec;

        for (const auto& rule : rule_list) {
            if (std::regex_search(buf, end, rule.Pattern)) {
                return true;
            }
        }
        return false;
    };

    auto matches_target = [&](const common::TargetAddress& target) {
        if (!target.IsValid()) {
            return false;
        }
        const std::string_view host(target.host.data(), target.host.size());
        if (!host.empty() && matches_host_port(host, target.port)) {
            return true;
        }
        if (target.resolved_addr) {
            const iputil::AddressText addr_text(*target.resolved_addr);
            if (addr_text.View() != host &&
                matches_host_port(addr_text.View(), target.port)) {
                return true;
            }
        }
        return false;
    };

    auto same_target = [](const common::TargetAddress& a, const common::TargetAddress& b) {
        return a.SameEndpoint(b) && a.resolved_addr == b.resolved_addr;
    };

    if (matches_target(ctx.outbound.target)) {
        return true;
    }
    if (ctx.outbound.route_target.IsValid() &&
        !same_target(ctx.outbound.route_target, ctx.outbound.target) &&
        matches_target(ctx.outbound.route_target)) {
        return true;
    }
    if (ctx.outbound.original_target.IsValid() &&
        !same_target(ctx.outbound.original_target, ctx.outbound.target) &&
        (!ctx.outbound.route_target.IsValid() ||
         !same_target(ctx.outbound.original_target, ctx.outbound.route_target)) &&
        matches_target(ctx.outbound.original_target)) {
        return true;
    }
    return false;
}

}  // namespace rule
