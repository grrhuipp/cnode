#include "acppnode/common/rule.hpp"

#include "acppnode/common/ip_utils.hpp"
#include "acppnode/common/session.hpp"

#include <algorithm>
#include <charconv>
#include <cstring>
#include <optional>
#include <regex>

namespace acpp::rule {

Manager::Manager() = default;
Manager::~Manager() = default;
Manager::Manager(Manager&&) noexcept = default;
Manager& Manager::operator=(Manager&&) noexcept = default;

void Manager::UpdateRule(std::string_view tag,
                         const std::vector<DetectRule>& new_rule_list) {
    if (tag.empty()) {
        return;
    }

    if (new_rule_list.empty()) {
        if (auto it = rules_.find(tag); it != rules_.end()) {
            rules_.erase(it);
        }
        return;
    }

    RuleList candidate(new_rule_list.begin(), new_rule_list.end());
    const auto it = rules_.find(tag);
    if (it == rules_.end()) {
        rules_.try_emplace(memory::ThreadLocalString(tag), std::move(candidate));
    } else {
        it->second.swap(candidate);
    }
}

bool Manager::Blocked(const session::Context& ctx) {
    if (ctx.inbound.user_id <= 0) {
        return false;
    }

    const auto rules_it = rules_.find(ctx.inbound.tag);
    if (rules_it == rules_.end()) {
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
