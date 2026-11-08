#pragma once

#include "features/routing/router.hpp"
#include "common/allocator.hpp"

#include <memory>

namespace geo {
class GeoDatabase;
}  // namespace geo

struct RoutingConfig;

namespace app::router {

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
    struct Impl;
    std::unique_ptr<const Impl> impl_;
};

}  // namespace app::router
