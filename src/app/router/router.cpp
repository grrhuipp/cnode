#include "app/router/router.hpp"

#include "common/allocator.hpp"
#include "common/asio_types.hpp"
#include "common/session.hpp"
#include "core/constants.hpp"
#include "geo/geodata.hpp"
#include "infra/config_types.hpp"
#include "infra/log.hpp"

#include <algorithm>
#include <optional>
#include <stdexcept>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace app::router {

namespace {
using StringVector = std::vector<std::string>;

void SortUniqueStrings(StringVector& values) {
    std::sort(values.begin(), values.end());
    values.erase(std::unique(values.begin(), values.end()), values.end());
}

[[nodiscard]] bool ContainsSortedString(
    const StringVector& values,
    std::string_view value) {
    const auto it = std::lower_bound(
        values.begin(), values.end(), value,
        [](const std::string& lhs, std::string_view rhs) {
            return std::string_view(lhs) < rhs;
        });
    return it != values.end() && std::string_view(*it) == value;
}

[[nodiscard]] std::string_view RoutingDomain(const session::Context& ctx) noexcept {
    if (ctx.outbound.route_target.IsValid() && ctx.outbound.route_target.IsDomain()) {
        return ctx.outbound.route_target.host;
    }
    if (ctx.outbound.target.IsDomain()) {
        return ctx.outbound.target.host;
    }
    return {};
}

[[nodiscard]] const net::ip::address* RoutingAddress(const session::Context& ctx) noexcept {
    if (ctx.outbound.route_target.IsValid() && ctx.outbound.route_target.resolved_addr) {
        return &*ctx.outbound.route_target.resolved_addr;
    }
    if (ctx.outbound.target.resolved_addr) {
        return &*ctx.outbound.target.resolved_addr;
    }
    return nullptr;
}

[[nodiscard]] std::span<const uint8_t> NetworkBytes(const RoutingIpNetwork& network) noexcept {
    return std::span<const uint8_t>(network.Network()).first(network.IsV6() ? 16 : 4);
}

}  // namespace

namespace detail {

constexpr uint8_t CompoundRoutingRule::ProtocolBit(std::string_view protocol) noexcept {
    if (protocol == constants::protocol::kTls) {
        return kProtocolTls;
    }
    if (protocol == constants::protocol::kHttp) {
        return kProtocolHttp;
    }
    if (protocol == constants::protocol::kBitTorrent) {
        return kProtocolBittorrent;
    }
    if (protocol == constants::protocol::kQuic) {
        return kProtocolQuic;
    }
    return 0;
}

void CompoundRoutingRule::SetNetworkCondition(const std::vector<std::string>& networks) {
    network_mask = 0;
    for (const auto& network : networks) {
        if (network == constants::protocol::kTcp) {
            network_mask |= kNetworkTcp;
        } else if (network == constants::protocol::kUdp) {
            network_mask |= kNetworkUdp;
        } else {
            throw std::logic_error(
                "non-normalized routing network reached runtime");
        }
    }
}

void CompoundRoutingRule::SetProtocolCondition(const std::vector<std::string>& protocols) {
    protocol_mask = 0;
    protocol_values.clear();
    for (const auto& protocol : protocols) {
        if (const uint8_t bit = ProtocolBit(protocol); bit != 0) {
            protocol_mask |= bit;
        } else {
            protocol_values.emplace_back(protocol);
        }
    }
    SortUniqueStrings(protocol_values);
}

void CompoundRoutingRule::SetInboundTagCondition(const std::vector<std::string>& tags) {
    inbound_tag_values.assign(tags.begin(), tags.end());
    SortUniqueStrings(inbound_tag_values);
}

void CompoundRoutingRule::SetUserCondition(const std::vector<std::string>& users) {
    user_values.assign(users.begin(), users.end());
    SortUniqueStrings(user_values);
}

void CompoundRoutingRule::SetPortCondition(const std::vector<RoutingPortRange>& ports) {
    port_ranges.assign(ports.begin(), ports.end());
}

void CompoundRoutingRule::SetSourcePortCondition(const std::vector<RoutingPortRange>& ports) {
    source_port_ranges.assign(ports.begin(), ports.end());
}

bool CompoundRoutingRule::HasAnyCondition() const noexcept {
    return network_mask != 0 || protocol_mask != 0 ||
           !protocol_values.empty() || !inbound_tag_values.empty() ||
           !user_values.empty() || !port_ranges.empty() ||
           !source_port_ranges.empty() ||
           source_ip_matcher.has_value() || ip_matcher.has_value() ||
           domain_matcher.has_value() || !geosite_sets.empty() ||
           !geoip_sets.empty();
}

bool CompoundRoutingRule::Match(
    const session::Context& ctx,
    std::string_view target_domain,
    const net::ip::address* target_addr,
    uint16_t target_port) const {
    if (network_mask != 0 && !MatchNetwork(ctx)) return false;
    if ((protocol_mask != 0 || !protocol_values.empty()) && !MatchProtocol(ctx)) return false;
    if (!inbound_tag_values.empty() && !MatchInboundTag(ctx)) return false;
    if (!user_values.empty() && !MatchUser(ctx)) return false;
    if (!source_port_ranges.empty() && !MatchPortRanges(source_port_ranges, ctx.inbound.source_port)) {
        return false;
    }
    if (!port_ranges.empty() && !MatchPortRanges(port_ranges, target_port)) {
        return false;
    }
    if (source_ip_matcher) {
        if (ctx.inbound.source_addr.is_unspecified() ||
            !source_ip_matcher->Match(ctx.inbound.source_addr)) {
            return false;
        }
    }
    if (ip_matcher && (!target_addr || !ip_matcher->Match(*target_addr))) {
        return false;
    }
    if (domain_matcher && (target_domain.empty() || !domain_matcher->Match(target_domain))) {
        return false;
    }
    if (!geosite_sets.empty()) {
        if (target_domain.empty() ||
            std::ranges::none_of(geosite_sets, [&](const ::geo::DomainRuleSet* set) {
                return set->Match(target_domain);
            })) {
            return false;
        }
    }
    if (!geoip_sets.empty()) {
        if (!target_addr ||
            std::ranges::none_of(geoip_sets, [&](const ::geo::CidrSet* set) {
                return set->Match(*target_addr);
            })) {
            return false;
        }
    }
    return true;
}

bool CompoundRoutingRule::MatchNetwork(const session::Context& ctx) const noexcept {
    const uint8_t bit = (ctx.content.network == Network::UDP) ? kNetworkUdp : kNetworkTcp;
    return (network_mask & bit) != 0;
}

bool CompoundRoutingRule::MatchProtocol(const session::Context& ctx) const {
    if (ctx.content.protocol.empty()) return false;

    const uint8_t bit = ProtocolBit(ctx.content.protocol);
    if (bit != 0) {
        return (protocol_mask & bit) != 0;
    }
    return ContainsSortedString(protocol_values, ctx.content.protocol);
}

bool CompoundRoutingRule::MatchInboundTag(const session::Context& ctx) const {
    if (ContainsSortedString(inbound_tag_values, ctx.inbound.tag)) {
        return true;
    }

    for (const auto& tag : ctx.inbound.tags) {
        if (tag == ctx.inbound.tag) continue;
        if (ContainsSortedString(inbound_tag_values, tag)) {
            return true;
        }
    }
    return false;
}

bool CompoundRoutingRule::MatchUser(const session::Context& ctx) const {
    return ContainsSortedString(user_values, ctx.inbound.user_email);
}

bool CompoundRoutingRule::MatchPortRanges(
    const std::vector<RoutingPortRange>& ranges,
    uint16_t port) noexcept {
    for (const auto& range : ranges) {
        if (port >= range.start && port <= range.end) return true;
    }
    return false;
}

}  // namespace detail

// ============================================================================
// Router 实现
// ============================================================================

Router::Router(const RoutingConfig& routing, const ::geo::GeoDatabase* geo)
    : domain_strategy_(routing.domain_strategy) {
    compound_rules_.reserve(routing.rules.size());
    for (const auto& rc : routing.rules) {
        if (rc.outbound_tag.empty()) {
            throw std::logic_error("routing rule without outbound tag reached runtime");
        }
        detail::CompoundRoutingRule compound;
        compound.outbound_tag = rc.outbound_tag;

        if (!rc.network.empty()) {
            compound.SetNetworkCondition(rc.network);
        }

        if (!rc.inbound_tag.empty()) {
            compound.SetInboundTagCondition(rc.inbound_tag);
        }

        if (!rc.user.empty()) {
            compound.SetUserCondition(rc.user);
        }

        if (!rc.source_port.empty()) {
            compound.SetSourcePortCondition(rc.source_port);
        }

        if (!rc.port.empty()) {
            compound.SetPortCondition(rc.port);
        }

        if (!rc.protocol.empty()) {
            compound.SetProtocolCondition(rc.protocol);
        }

        if (!rc.source.empty()) {
            auto& source_ip_matcher =
                compound.source_ip_matcher.emplace(memory::process_resource());
            for (const auto& value : rc.source) {
                source_ip_matcher.Insert(NetworkBytes(value), value.Prefix());
            }
            if (source_ip_matcher.Empty()) {
                compound.source_ip_matcher.reset();
            }
        }

        if (!rc.ip.empty()) {
            auto& ip_matcher =
                compound.ip_matcher.emplace(memory::process_resource());
            for (const auto& value : rc.ip) {
                ip_matcher.Insert(NetworkBytes(value), value.Prefix());
            }
            if (ip_matcher.Empty()) {
                compound.ip_matcher.reset();
            }
        }

        if (!rc.domain_suffix.empty() || !rc.domain_keyword.empty() ||
            !rc.domain_full.empty() || !rc.domain_regex.empty()) {
            auto& domain_matcher =
                compound.domain_matcher.emplace(memory::process_resource());
            for (const auto& value : rc.domain_suffix) {
                domain_matcher.AddSuffix(value);
            }
            for (const auto& value : rc.domain_keyword) {
                domain_matcher.AddKeyword(value);
            }
            for (const auto& value : rc.domain_full) {
                domain_matcher.AddFull(value);
            }
            for (const auto& value : rc.domain_regex) {
                domain_matcher.AddRegex(value);
            }
            if (domain_matcher.Empty()) {
                compound.domain_matcher.reset();
            }
        }

        if (!rc.geosite.empty()) {
            if (!geo) {
                throw std::logic_error(
                    "geosite condition reached runtime without GeoDatabase");
            }
            compound.geosite_sets.reserve(rc.geosite.size());
            for (const auto& tag : rc.geosite) {
                const auto* set = geo->FindGeoSite(tag);
                if (!set) {
                    throw std::logic_error(
                        "unresolved geosite tag reached routing runtime");
                }
                compound.geosite_sets.push_back(set);
            }
        }

        if (!rc.geoip.empty()) {
            if (!geo) {
                throw std::logic_error(
                    "geoip condition reached runtime without GeoDatabase");
            }
            compound.geoip_sets.reserve(rc.geoip.size());
            for (const auto& tag : rc.geoip) {
                const auto* set = geo->FindGeoIP(tag);
                if (!set) {
                    throw std::logic_error(
                        "unresolved geoip tag reached routing runtime");
                }
                compound.geoip_sets.push_back(set);
            }
        }

        if (!compound.HasAnyCondition()) {
            throw std::logic_error(
                "routing rule without conditions reached runtime");
        }
        compound_rules_.push_back(std::move(compound));
    }
}

Router::~Router() noexcept = default;

routing::RouteDecision Router::Route(const session::Context& ctx) const {
    const auto& target = ctx.outbound.target;
    const std::string_view target_domain = RoutingDomain(ctx);
    const net::ip::address* const target_addr = RoutingAddress(ctx);
    const uint16_t target_port = ctx.outbound.route_target.IsValid()
        ? ctx.outbound.route_target.port
        : target.port;

    // 顺序检查复合规则（AND 语义）
    for (const auto& rule : compound_rules_) {
        if (rule.Match(ctx, target_domain, target_addr, target_port)) {
            LOG_CONN_DEBUG(ctx, "matched compound routing rule target={} outbound={}",
                      target, rule.outbound_tag);
            return routing::RouteDecision{
                .outbound_tag = rule.outbound_tag,
                .matched = true,
            };
        }
    }
    // No match is an explicit empty decision. Dispatcher owns the receiver's
    // explicit fallback.
    LOG_CONN_DEBUG(ctx, "no matching routing rule target={}", target);
    return routing::RouteDecision{
        .outbound_tag = {},
        .matched = false,
    };
}

routing::DomainStrategy Router::DomainStrategy() const noexcept {
    return domain_strategy_;
}
}  // namespace app::router
