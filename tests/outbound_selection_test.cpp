#include <gtest/gtest.h>

#include "app/dispatcher/outbound_selection.hpp"

#include <concepts>
#include <stdexcept>


TEST(OutboundSelection, Contract) {
    using acpp::app::dispatcher::detail::RequiresRouting;
    using acpp::routing::RouteDecision;
    using acpp::app::dispatcher::detail::SelectionSource;
    using acpp::app::dispatcher::detail::SelectOutbound;

    try {
        (void)acpp::routing::ForceOutbound("");
        FAIL() << "empty forced outbound tag must be rejected";
    } catch (const std::invalid_argument&) {
    }
    try {
        (void)acpp::routing::RouteWithFallback("");
        FAIL() << "empty route fallback tag must be rejected";
    } catch (const std::invalid_argument&) {
    }

    const acpp::routing::OutboundSelectionPolicy forced =
        acpp::routing::ForceOutbound("direct");
    ASSERT_FALSE((RequiresRouting(forced)));
    const auto forced_selection = SelectOutbound(
        forced,
        RouteDecision{
            .outbound_tag = "blocked",
            .matched = true,
        });
    ASSERT_FALSE((forced_selection.outbound_tag != "direct" ||
        forced_selection.source != SelectionSource::Forced));

    const acpp::routing::OutboundSelectionPolicy routed =
        acpp::routing::RouteWithFallback("panel-direct");
    ASSERT_FALSE((!RequiresRouting(routed)));
    const auto rule_selection = SelectOutbound(
        routed,
        RouteDecision{
            .outbound_tag = "proxy",
            .matched = true,
        });
    ASSERT_FALSE((rule_selection.outbound_tag != "proxy" ||
        rule_selection.source != SelectionSource::Rule));

    const auto fallback_selection = SelectOutbound(routed);
    ASSERT_FALSE((fallback_selection.outbound_tag != "panel-direct" ||
        fallback_selection.source != SelectionSource::Fallback));

}
