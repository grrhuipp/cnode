#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>

namespace acpp::geo {
class GeoManager;
}  // namespace acpp::geo

namespace acpp {
struct RoutingConfig;
enum class RoutingDomainStrategy : uint8_t;
namespace session {
struct Context;
}  // namespace session
}  // namespace acpp

namespace acpp::app::router {

struct RouteDecision {
    std::string_view outbound_tag;
    bool matched = false;
    uint32_t rule_index = 0;
};

class Router {
public:
    Router();
    ~Router() noexcept;
    Router(Router&&) noexcept;
    Router& operator=(Router&&) noexcept;
    Router(const Router&) = delete;
    Router& operator=(const Router&) = delete;

    // Cold path: build immutable routing matchers from normalized runtime config.
    void Configure(
        const RoutingConfig& routing,
        ::acpp::geo::GeoManager* geo_manager);

    // Hot path: return a tag only when a normalized routing rule matches.
    [[nodiscard]] RouteDecision RouteDetailed(const session::Context& ctx) const;

    [[nodiscard]] ::acpp::RoutingDomainStrategy DomainStrategy() const noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace acpp::app::router
