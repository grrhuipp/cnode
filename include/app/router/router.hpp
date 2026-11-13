#pragma once

#include "common/asio_types.hpp"
#include "routing/router.hpp"
#include "geo/geodata.hpp"
#include "infra/config_types.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace app {

struct CompoundRoutingRule {
    void SetNetworkCondition(const std::vector<std::string>& networks);
    void SetProtocolCondition(const std::vector<std::string>& protocols);
    void SetInboundTagCondition(const std::vector<std::string>& tags);
    void SetUserCondition(const std::vector<std::string>& users);
    void SetPortCondition(const std::vector<infra::RoutingPortRange>& ports);
    void SetSourcePortCondition(const std::vector<infra::RoutingPortRange>& ports);
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
    std::vector<infra::RoutingPortRange> port_ranges;
    std::vector<infra::RoutingPortRange> source_port_ranges;

    [[nodiscard]] bool Match(
        const common::Context& ctx,
        std::string_view target_domain,
        const net::ip::address* target_addr,
        uint16_t target_port) const;

private:
    static constexpr uint8_t kNetworkTcp = 1u << 0;
    static constexpr uint8_t kNetworkUdp = 1u << 1;

    [[nodiscard]] bool MatchNetwork(const common::Context& ctx) const noexcept;
    [[nodiscard]] bool MatchProtocol(const common::Context& ctx) const;
    [[nodiscard]] bool MatchInboundTag(const common::Context& ctx) const;
    [[nodiscard]] bool MatchUser(const common::Context& ctx) const;
    [[nodiscard]] static bool MatchPortRanges(
        const std::vector<infra::RoutingPortRange>& ranges,
        uint16_t port) noexcept;
};

class Router final : public ::routing::Router {
public:
    // Immutable routing snapshot shared across Workers.
    // Failed builds never publish partial matchers.
    Router(const infra::RoutingConfig& config, const ::geo::GeoDatabase* geo_database);
    ~Router() noexcept override;
    Router(const Router&) = delete;
    Router& operator=(const Router&) = delete;

    // Hot path: return a tag only when a normalized routing rule matches.
    [[nodiscard]] ::routing::RouteDecision Route(const common::Context& ctx) const override;

    [[nodiscard]] ::routing::DomainStrategy DomainStrategy() const noexcept override;
    [[nodiscard]] size_t RuleCount() const noexcept { return compound_rules_.size(); }

private:
    std::vector<CompoundRoutingRule> compound_rules_;
    ::routing::DomainStrategy domain_strategy_;
};

}  // namespace app
