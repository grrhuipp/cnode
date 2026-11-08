#include "common/rule.hpp"

#include "common/ip_utils.hpp"
#include "common/session.hpp"

#include <algorithm>
#include <charconv>
#include <cstring>
#include <optional>
#include <regex>

namespace rule {

DetectRulePolicy::DetectRulePolicy()
    : rules_(std::make_shared<const InboundRule>()) {}
DetectRulePolicy::~DetectRulePolicy() = default;

void DetectRulePolicy::UpdateRule(std::string_view tag,
                                  std::vector<DetectRule> new_rule_list) {
    if (tag.empty()) return;
    const std::lock_guard lock(update_mutex_);
    auto next = std::make_shared<InboundRule>(*rules_.load(std::memory_order_acquire));
    if (new_rule_list.empty()) {
        if (auto it = next->find(tag); it != next->end()) next->erase(it);
    } else {
        next->insert_or_assign(std::string(tag), std::move(new_rule_list));
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

    auto matches_host_port = [&](std::string_view host, uint16_t port) {
        if (host.empty()) {
            return false;
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
        auto [end, ec] = std::to_chars(out, buf + sizeof(buf), port);
        (void)ec;

        for (const auto& rule : rules_it->second) {
            if (std::regex_search(buf, end, rule.Pattern)) {
                return true;
            }
        }
        return false;
    };

    auto matches_target = [&](const TargetAddress& target) {
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

    auto same_target = [](const TargetAddress& a, const TargetAddress& b) {
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
