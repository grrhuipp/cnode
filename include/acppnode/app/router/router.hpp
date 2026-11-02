#pragma once

#include "acppnode/features/routing/router.hpp"

#include <memory>

namespace acpp::geo {
class GeoManager;
}  // namespace acpp::geo

namespace acpp {
struct RoutingConfig;
}  // namespace acpp

namespace acpp::app::router {

class Router final : public routing::Router {
public:
    // Build on the owning Worker before binding to Dispatcher. Failed builds
    // never publish partial matchers, and a published Router cannot be changed.
    Router(const RoutingConfig& config, const ::acpp::geo::GeoManager* geo_manager);
    ~Router() noexcept override;
    Router(const Router&) = delete;
    Router& operator=(const Router&) = delete;

    // Hot path: return a tag only when a normalized routing rule matches.
    [[nodiscard]] routing::RouteDecision Route(const session::Context& ctx) const override;

    [[nodiscard]] routing::DomainStrategy DomainStrategy() const noexcept override;

private:
    struct Impl;
    std::unique_ptr<const Impl> impl_;
};

}  // namespace acpp::app::router
