#include <gtest/gtest.h>
#include "app/dispatcher/default_dispatcher.hpp"
#include <stdexcept>
#include <utility>

namespace {
template <typename Policy>
concept SelectablePolicy = requires(Policy&& policy) {
    ::app::SelectOutbound(std::forward<Policy>(policy));
};
static_assert(SelectablePolicy<::routing::OutboundSelectionPolicy&>);
static_assert(SelectablePolicy<const ::routing::OutboundSelectionPolicy&>);
static_assert(!SelectablePolicy<::routing::OutboundSelectionPolicy>);
static_assert(!SelectablePolicy<const ::routing::OutboundSelectionPolicy>);
static_assert(!SelectablePolicy<::routing::ForceOutbound>);
static_assert(!SelectablePolicy<::routing::ForceOutbound&>);
static_assert(!SelectablePolicy<::routing::RouteWithFallback>);
static_assert(!SelectablePolicy<::routing::RouteWithFallback&>);
}  // namespace

TEST(OutboundSelection, RejectsEmptyForcedAndFallbackTags) {
    EXPECT_THROW((void)::routing::ForceOutbound(""), std::invalid_argument);
    EXPECT_THROW((void)::routing::RouteWithFallback(""), std::invalid_argument);
}

TEST(OutboundSelection, ForcedTagOverridesMatchedRoute) {
    // Selection borrows the variant's tag, not the converting policy temporary.
    const ::routing::OutboundSelectionPolicy policy = ::routing::ForceOutbound("direct");
    EXPECT_FALSE(::app::RequiresRouting(policy));
    const auto selected = ::app::SelectOutbound(
        policy, ::routing::RouteDecision{.outbound_tag = "blocked", .matched = true});
    EXPECT_EQ(selected.outbound_tag, "direct");
    EXPECT_EQ(selected.source, ::app::SelectionSource::Forced);
}

TEST(OutboundSelection, MatchedRuleOverridesFallback) {
    const ::routing::OutboundSelectionPolicy policy = ::routing::RouteWithFallback("panel-direct");
    EXPECT_TRUE(::app::RequiresRouting(policy));
    const auto selected = ::app::SelectOutbound(
        policy, ::routing::RouteDecision{.outbound_tag = "proxy", .matched = true});
    EXPECT_EQ(selected.outbound_tag, "proxy");
    EXPECT_EQ(selected.source, ::app::SelectionSource::Rule);
}

TEST(OutboundSelection, MissingRuleUsesFallback) {
    const ::routing::OutboundSelectionPolicy policy = ::routing::RouteWithFallback("panel-direct");
    const auto selected = ::app::SelectOutbound(policy);
    EXPECT_EQ(selected.outbound_tag, "panel-direct");
    EXPECT_EQ(selected.source, ::app::SelectionSource::Fallback);
}
