#pragma once

#include "features/routing/dispatch_policy.hpp"
#include "features/routing/router.hpp"

#include <cassert>
#include <cstdint>
#include <string_view>
#include <variant>

namespace app::dispatcher::detail {

enum class SelectionSource : uint8_t {
    Forced,
    Rule,
    Fallback,
};

struct OutboundSelection {
    std::string_view outbound_tag;
    SelectionSource source = SelectionSource::Fallback;
};

[[nodiscard]] inline bool RequiresRouting(
    const routing::OutboundSelectionPolicy& policy) noexcept {
    return std::holds_alternative<routing::RouteWithFallback>(policy);
}

[[nodiscard]] inline OutboundSelection SelectOutbound(
    const routing::OutboundSelectionPolicy& policy,
    const routing::RouteDecision& rule = {}) noexcept {
    if (const auto* forced = std::get_if<routing::ForceOutbound>(&policy)) {
        return OutboundSelection{
            .outbound_tag = forced->outbound_tag,
            .source = SelectionSource::Forced,
        };
    }

    const auto* routed = std::get_if<routing::RouteWithFallback>(&policy);
    assert(routed != nullptr);
    if (rule.matched) {
        return OutboundSelection{
            .outbound_tag = rule.outbound_tag,
            .source = SelectionSource::Rule,
        };
    }
    return OutboundSelection{
        .outbound_tag = routed->outbound_tag,
        .source = SelectionSource::Fallback,
    };
}

}  // namespace app::dispatcher::detail
