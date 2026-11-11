#pragma once

#include "common/allocator.hpp"
#include "common/asio_types.hpp"
#include "features/routing/router.hpp"
#include "geo/geodata.hpp"
#include "infra/config_types.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace app::router {

namespace detail {

struct CompoundRoutingRule {
    void SetNetworkCondition(const std::vector<std::string>& networks);
    void SetProtocolCondition(const std::vector<std::string>& protocols);
    void SetInboundTagCondition(const std::vector<std::string>& tags);
    void SetUserCondition(const std::vector<std::string>& users);
    void SetPortCondition(const std::vector<RoutingPortRange>& ports);
    void SetSourcePortCondition(const std::vector<RoutingPortRange>& ports);
    [[nodiscard]] bool HasAnyCondition() const noexcept;

    std::optional<::geo::CidrSet> source_ip_matcher;
    std::optional<::geo::CidrSet> ip_matcher;
    std::optional<::geo::DomainRuleSet> domain_matcher;
    std::vector<const ::geo::DomainRuleSet*> geosite_sets;
    std::vector<const ::geo::CidrSet*> geoip_sets;
    std::string outbound_tag;
    uint8_t network_mask = 0;
    uint8_t protocol_mask = 0;
    std::vector<std::string> protocol_values;
    std::vector<std::string> inbound_tag_values;
    std::vector<std::string> user_values;
    std::vector<RoutingPortRange> port_ranges;
    std::vector<RoutingPortRange> source_port_ranges;

    [[nodiscard]] bool Match(
        const session::Context& ctx,
        std::string_view target_domain,
        const net::ip::address* target_addr,
        uint16_t target_port) const;

private:
    static constexpr uint8_t kNetworkTcp = 1u << 0;
    static constexpr uint8_t kNetworkUdp = 1u << 1;

    [[nodiscard]] bool MatchNetwork(const session::Context& ctx) const noexcept;
    [[nodiscard]] bool MatchProtocol(const session::Context& ctx) const;
    [[nodiscard]] bool MatchInboundTag(const session::Context& ctx) const;
    [[nodiscard]] bool MatchUser(const session::Context& ctx) const;
    [[nodiscard]] static bool MatchPortRanges(
        const std::vector<RoutingPortRange>& ranges,
        uint16_t port) noexcept;
};

}  // namespace detail

class Router final : public routing::Router {
public:
    // Immutable process-allocated routing snapshot, shared by session domains.
    // Failed builds never publish partial matchers.
    Router(const RoutingConfig& config, const ::geo::GeoDatabase* geo_database);
    ~Router() noexcept override;
    Router(const Router&) = delete;
    Router& operator=(const Router&) = delete;

    // Hot path: return a tag only when a normalized routing rule matches.
    [[nodiscard]] routing::RouteDecision Route(const session::Context& ctx) const override;

    [[nodiscard]] routing::DomainStrategy DomainStrategy() const noexcept override;

private:
    std::vector<detail::CompoundRoutingRule> compound_rules_;
    routing::DomainStrategy domain_strategy_;
};

}  // namespace app::router
