#pragma once

#include "acppnode/proxy/sniff_config.hpp"

#include <stdexcept>
#include <string>
#include <utility>
#include <variant>

namespace acpp::routing {

// Dispatcher-owned outbound selection policy. Both alternatives require an
// explicit target, so a receiver cannot accidentally inherit mutable process
// state or enter the hot path without a complete selection policy.
struct ForceOutbound {
    explicit ForceOutbound(std::string tag)
        : outbound_tag(std::move(tag)) {
        if (outbound_tag.empty()) {
            throw std::invalid_argument("forced outbound tag must not be empty");
        }
    }

    std::string outbound_tag;
};

struct RouteWithFallback {
    explicit RouteWithFallback(std::string tag)
        : outbound_tag(std::move(tag)) {
        if (outbound_tag.empty()) {
            throw std::invalid_argument("routing fallback tag must not be empty");
        }
    }

    std::string outbound_tag;
};

using OutboundSelectionPolicy = std::variant<ForceOutbound, RouteWithFallback>;

// Immutable after receiver preparation. Inbound handlers, Mux children and
// native UDP sessions pass only this narrow hot-path contract to Dispatcher.
struct DispatchPolicy {
    SniffConfig sniffing;
    OutboundSelectionPolicy outbound;
};

}  // namespace acpp::routing
