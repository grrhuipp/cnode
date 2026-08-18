#include "app/dispatcher/outbound_selection.hpp"

#include <concepts>
#include <stdexcept>

static_assert(!std::default_initializable<acpp::routing::ForceOutbound>);
static_assert(!std::default_initializable<acpp::routing::RouteWithFallback>);
static_assert(!std::default_initializable<acpp::routing::OutboundSelectionPolicy>);
static_assert(!std::default_initializable<acpp::routing::DispatchPolicy>);

int main() {
    using acpp::app::dispatcher::detail::RequiresRouting;
    using acpp::app::dispatcher::detail::RuleSelection;
    using acpp::app::dispatcher::detail::SelectionSource;
    using acpp::app::dispatcher::detail::SelectOutbound;

    try {
        (void)acpp::routing::ForceOutbound("");
        return 1;
    } catch (const std::invalid_argument&) {
    }
    try {
        (void)acpp::routing::RouteWithFallback("");
        return 2;
    } catch (const std::invalid_argument&) {
    }

    const acpp::routing::OutboundSelectionPolicy forced =
        acpp::routing::ForceOutbound("direct");
    if (RequiresRouting(forced)) return 3;
    const auto forced_selection = SelectOutbound(
        forced,
        RuleSelection{
            .outbound_tag = "blocked",
            .matched = true,
            .rule_index = 7,
        });
    if (forced_selection.outbound_tag != "direct" ||
        forced_selection.source != SelectionSource::Forced) {
        return 4;
    }

    const acpp::routing::OutboundSelectionPolicy routed =
        acpp::routing::RouteWithFallback("panel-direct");
    if (!RequiresRouting(routed)) return 5;
    const auto rule_selection = SelectOutbound(
        routed,
        RuleSelection{
            .outbound_tag = "proxy",
            .matched = true,
            .rule_index = 11,
        });
    if (rule_selection.outbound_tag != "proxy" ||
        rule_selection.source != SelectionSource::Rule ||
        rule_selection.rule_index != 11) {
        return 6;
    }

    const auto fallback_selection = SelectOutbound(routed);
    if (fallback_selection.outbound_tag != "panel-direct" ||
        fallback_selection.source != SelectionSource::Fallback) {
        return 7;
    }

    return 0;
}
