#pragma once

#include "acppnode/proxy/sniff_config.hpp"

#include <cstdint>
#include <string>
#include <utility>

namespace acpp::routing {

// Dispatcher-owned outbound selection priority. Router rules remain a pure
// match decision and never own forced or no-match fallback semantics.
enum class OutboundSelectionKind : uint8_t {
    Route,
    ForceOutbound,
    RouteWithFallback,
};

struct OutboundSelectionPolicy {
    OutboundSelectionKind kind = OutboundSelectionKind::Route;
    std::string outbound_tag;

    [[nodiscard]] static OutboundSelectionPolicy Route() {
        return {};
    }

    [[nodiscard]] static OutboundSelectionPolicy Force(std::string tag) {
        if (tag.empty()) {
            return {};
        }
        OutboundSelectionPolicy policy;
        policy.kind = OutboundSelectionKind::ForceOutbound;
        policy.outbound_tag = std::move(tag);
        return policy;
    }

    [[nodiscard]] static OutboundSelectionPolicy RouteWithFallback(
        std::string tag) {
        if (tag.empty()) {
            return {};
        }
        OutboundSelectionPolicy policy;
        policy.kind = OutboundSelectionKind::RouteWithFallback;
        policy.outbound_tag = std::move(tag);
        return policy;
    }

    [[nodiscard]] bool HasOutboundTag() const noexcept {
        return !outbound_tag.empty();
    }
};

// Immutable after receiver preparation. Inbound handlers, Mux children and
// native UDP sessions pass only this narrow hot-path contract to Dispatcher.
struct DispatchPolicy {
    SniffConfig sniffing;
    OutboundSelectionPolicy outbound;
};

}  // namespace acpp::routing
