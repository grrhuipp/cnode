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
        std::string_view default_outbound_tag,
        ::acpp::geo::GeoManager* geo_manager);

    // Cold path: switch only the fallback outbound without rebuilding matchers.
    void SetDefaultOutbound(std::string default_outbound_tag) noexcept;

    // Hot path: return the selected outbound tag, or the configured default tag.
    [[nodiscard]] std::string_view Route(const session::Context& ctx) const;
    [[nodiscard]] std::string_view Route(
        const session::Context& ctx,
        std::string_view default_outbound_tag) const;
    [[nodiscard]] RouteDecision RouteDetailed(const session::Context& ctx) const;
    [[nodiscard]] RouteDecision RouteDetailed(
        const session::Context& ctx,
        std::string_view default_outbound_tag) const;

    [[nodiscard]] std::string_view DefaultOutbound() const;
    [[nodiscard]] ::acpp::RoutingDomainStrategy DomainStrategy() const noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace acpp::app::router
