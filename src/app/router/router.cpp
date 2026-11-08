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

// geosite / geoip 条件在构建期解析为 GeoDatabase 内只读集合的指针；
// GeoDatabase 生命周期覆盖所有 Worker 的 Router。
class GeoSiteCondition {
public:
    GeoSiteCondition(
        const std::vector<std::string>& tags,
        const ::geo::GeoDatabase* geo);

    [[nodiscard]] bool Match(const session::Context& ctx) const;

private:
    std::vector<const ::geo::DomainRuleSet*> sets_;
};

class GeoIPCondition {
public:
    GeoIPCondition(
        const std::vector<std::string>& tags,
        const ::geo::GeoDatabase* geo);

    [[nodiscard]] bool Match(const session::Context& ctx) const;

private:
    std::vector<const ::geo::CidrSet*> sets_;
};

struct CompoundRoutingRule {
    void SetNetworkCondition(const std::vector<std::string>& networks) {
        has_network_condition = true;
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

    void SetProtocolCondition(const std::vector<std::string>& protocols) {
        has_protocol_condition = true;
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

    void SetInboundTagCondition(const std::vector<std::string>& tags) {
        has_inbound_tag_condition = true;
        inbound_tag_values.clear();
        inbound_tag_values.reserve(tags.size());
        for (const auto& tag : tags) {
            inbound_tag_values.emplace_back(tag);
        }
        SortUniqueStrings(inbound_tag_values);
    }

    void SetUserCondition(const std::vector<std::string>& users) {
        has_user_condition = true;
        user_values.clear();
        user_values.reserve(users.size());
        for (const auto& user : users) {
            user_values.emplace_back(user);
        }
        SortUniqueStrings(user_values);
    }

    void SetPortCondition(const std::vector<RoutingPortRange>& ports) {
        has_port_condition = true;
        port_ranges.assign(ports.begin(), ports.end());
    }

    void SetSourcePortCondition(const std::vector<RoutingPortRange>& ports) {
        has_source_port_condition = true;
        source_port_ranges.assign(ports.begin(), ports.end());
    }

    [[nodiscard]] bool HasAnyCondition() const noexcept {
        return has_network_condition || has_protocol_condition ||
               has_inbound_tag_condition || has_user_condition ||
               has_port_condition || has_source_port_condition ||
               source_ip_matcher.has_value() || ip_matcher.has_value() ||
               domain_matcher.has_value() || geosite_condition.has_value() ||
               geoip_condition.has_value();
    }

    std::optional<::geo::CidrSet> source_ip_matcher;
    std::optional<::geo::CidrSet> ip_matcher;
    std::optional<::geo::DomainRuleSet> domain_matcher;
    std::optional<GeoSiteCondition> geosite_condition;
    std::optional<GeoIPCondition> geoip_condition;
    std::string outbound_tag;
    bool has_network_condition = false;
    bool has_protocol_condition = false;
    bool has_inbound_tag_condition = false;
    bool has_user_condition = false;
    bool has_port_condition = false;
    bool has_source_port_condition = false;
    uint8_t network_mask = 0;
    uint8_t protocol_mask = 0;
    StringVector protocol_values;
    StringVector inbound_tag_values;
    StringVector user_values;
    std::vector<RoutingPortRange> port_ranges;
    std::vector<RoutingPortRange> source_port_ranges;

    [[nodiscard]] bool Match(const session::Context& ctx) const {
        if (!HasAnyCondition()) return false;
        if (has_network_condition && !MatchNetwork(ctx)) return false;
        if (has_protocol_condition && !MatchProtocol(ctx)) return false;
        if (has_inbound_tag_condition && !MatchInboundTag(ctx)) return false;
        if (has_user_condition && !MatchUser(ctx)) return false;
        if (has_source_port_condition && !MatchPortRanges(source_port_ranges, ctx.inbound.source_port)) {
            return false;
        }
        const uint16_t target_port = ctx.outbound.route_target.IsValid()
            ? ctx.outbound.route_target.port
            : ctx.outbound.target.port;
        if (has_port_condition && !MatchPortRanges(port_ranges, target_port)) {
            return false;
        }
        if (source_ip_matcher) {
            if (ctx.inbound.source_addr.is_unspecified() ||
                !source_ip_matcher->Match(ctx.inbound.source_addr)) {
                return false;
            }
        }
        if (ip_matcher) {
            const auto* addr = RoutingAddress(ctx);
            if (!addr || !ip_matcher->Match(*addr)) {
                return false;
            }
        }
        if (domain_matcher) {
            const auto domain = RoutingDomain(ctx);
            if (domain.empty() || !domain_matcher->Match(domain)) {
                return false;
            }
        }
        if (geosite_condition && !geosite_condition->Match(ctx)) {
            return false;
        }
        if (geoip_condition && !geoip_condition->Match(ctx)) {
            return false;
        }
        return true;
    }

private:
    static constexpr uint8_t kNetworkTcp = 1u << 0;
    static constexpr uint8_t kNetworkUdp = 1u << 1;
    static constexpr uint8_t kProtocolTls = 1u << 0;
    static constexpr uint8_t kProtocolHttp = 1u << 1;
    static constexpr uint8_t kProtocolBittorrent = 1u << 2;
    static constexpr uint8_t kProtocolQuic = 1u << 3;

    [[nodiscard]] bool MatchNetwork(const session::Context& ctx) const noexcept {
        const uint8_t bit = (ctx.content.network == Network::UDP) ? kNetworkUdp : kNetworkTcp;
        return (network_mask & bit) != 0;
    }

    [[nodiscard]] bool MatchProtocol(const session::Context& ctx) const {
        if (ctx.content.protocol.empty()) return false;

        const uint8_t bit = ProtocolBit(ctx.content.protocol);
        if (bit != 0) {
            return (protocol_mask & bit) != 0;
        }
        return ContainsSortedString(protocol_values, ctx.content.protocol);
    }

    [[nodiscard]] bool MatchInboundTag(const session::Context& ctx) const {
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

    [[nodiscard]] bool MatchUser(const session::Context& ctx) const {
        return ContainsSortedString(user_values, ctx.inbound.user_email);
    }

    [[nodiscard]] static bool MatchPortRanges(
        const std::vector<RoutingPortRange>& ranges,
        uint16_t port) noexcept {
        for (const auto& range : ranges) {
            if (port >= range.start && port <= range.end) return true;
        }
        return false;
    }

    [[nodiscard]] static constexpr uint8_t ProtocolBit(std::string_view protocol) noexcept {
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
};
}  // namespace

// ============================================================================
// Router 实现
// ============================================================================

struct Router::Impl {
    Impl(const RoutingConfig& routing, const ::geo::GeoDatabase* geo);

    std::vector<CompoundRoutingRule> compound_rules;
    routing::DomainStrategy domain_strategy;
};

Router::Router(const RoutingConfig& config, const ::geo::GeoDatabase* geo_database)
    : impl_(std::make_unique<const Impl>(config, geo_database)) {}
Router::~Router() noexcept = default;

routing::RouteDecision Router::Route(const session::Context& ctx) const {
    const auto& target = ctx.outbound.target;

    // 顺序检查复合规则（AND 语义）
    for (const auto& rule : impl_->compound_rules) {
        if (rule.Match(ctx)) {
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

Router::Impl::Impl(
    const RoutingConfig& routing,
    const ::geo::GeoDatabase* geo)
    : domain_strategy(routing.domain_strategy) {
    compound_rules.reserve(routing.rules.size());
    for (const auto& rc : routing.rules) {
        if (rc.outbound_tag.empty()) {
            throw std::logic_error("routing rule without outbound tag reached runtime");
        }
        CompoundRoutingRule compound;
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

        ::geo::CidrSet source_ip_matcher(memory::process_resource());
        for (const auto& value : rc.source) {
            source_ip_matcher.Insert(NetworkBytes(value), value.Prefix());
        }
        if (!source_ip_matcher.Empty()) {
            compound.source_ip_matcher.emplace(std::move(source_ip_matcher));
        }

        ::geo::CidrSet ip_matcher(memory::process_resource());
        for (const auto& value : rc.ip) {
            ip_matcher.Insert(NetworkBytes(value), value.Prefix());
        }
        if (!ip_matcher.Empty()) {
            compound.ip_matcher.emplace(std::move(ip_matcher));
        }

        ::geo::DomainRuleSet domain_matcher(memory::process_resource());
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
        if (!domain_matcher.Empty()) {
            compound.domain_matcher.emplace(std::move(domain_matcher));
        }

        if (!rc.geosite.empty()) {
            compound.geosite_condition.emplace(rc.geosite, geo);
        }

        if (!rc.geoip.empty()) {
            compound.geoip_condition.emplace(rc.geoip, geo);
        }

        if (!compound.HasAnyCondition()) {
            throw std::logic_error(
                "routing rule without conditions reached runtime");
        }
        compound_rules.push_back(std::move(compound));
    }
}

routing::DomainStrategy Router::DomainStrategy() const noexcept {
    return impl_->domain_strategy;
}

bool GeoSiteCondition::Match(const session::Context& ctx) const {
    const auto domain = RoutingDomain(ctx);
    if (domain.empty()) return false;
    for (const auto* set : sets_) {
        if (set->Match(domain)) return true;
    }
    return false;
}

GeoSiteCondition::GeoSiteCondition(
    const std::vector<std::string>& tags,
    const ::geo::GeoDatabase* geo) {
    if (!geo) {
        throw std::logic_error(
            "geosite condition reached runtime without GeoDatabase");
    }
    sets_.reserve(tags.size());
    for (const auto& tag : tags) {
        const auto* set = geo->FindGeoSite(tag);
        if (!set) {
            throw std::logic_error(
                "unresolved geosite tag reached routing runtime");
        }
        sets_.push_back(set);
    }
}

bool GeoIPCondition::Match(const session::Context& ctx) const {
    const auto* addr = RoutingAddress(ctx);
    if (!addr) return false;
    for (const auto* set : sets_) {
        if (set->Match(*addr)) return true;
    }
    return false;
}

GeoIPCondition::GeoIPCondition(
    const std::vector<std::string>& tags,
    const ::geo::GeoDatabase* geo) {
    if (!geo) {
        throw std::logic_error(
            "geoip condition reached runtime without GeoDatabase");
    }
    sets_.reserve(tags.size());
    for (const auto& tag : tags) {
        const auto* set = geo->FindGeoIP(tag);
        if (!set) {
            throw std::logic_error(
                "unresolved geoip tag reached routing runtime");
        }
        sets_.push_back(set);
    }
}

}  // namespace app::router
