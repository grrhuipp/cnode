#pragma once

#include "acppnode/app/proxyman/outbound/prepared_config.hpp"
#include "acppnode/infra/config_types.hpp"
#include "acppnode/infra/runtime_config_types.hpp"

#include <cstddef>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace acpp {

enum class ConfigSemanticError {
    None,
    NoOutbounds,
    EmptyOutboundTag,
    ReservedOutboundTag,
    DuplicateOutboundTag,
    EmptyRouteOutboundTag,
    UnknownRouteOutboundTag,
    EmptyStaticInboundOutboundTag,
    UnknownStaticInboundOutboundTag,
};

struct ConfigSemanticValidation {
    ConfigSemanticError error = ConfigSemanticError::None;
    size_t index = 0;
    std::string_view tag;

    [[nodiscard]] bool Ok() const noexcept {
        return error == ConfigSemanticError::None;
    }
};

struct IgnoredRouteRule {
    size_t index = 0;
    std::string tag;
};

enum class StaticInboundSemanticError {
    None,
    InvalidPort,
    EmptyTag,
    ReservedTag,
    DuplicateTag,
    DuplicateEndpoint,
};

struct StaticInboundSemanticValidation {
    StaticInboundSemanticError error = StaticInboundSemanticError::None;
    size_t index = 0;
    size_t conflicting_index = 0;
    std::string detail;

    [[nodiscard]] bool Ok() const noexcept {
        return error == StaticInboundSemanticError::None;
    }

    [[nodiscard]] std::string Message() const;
};

[[nodiscard]] ConfigSemanticValidation ValidateOutboundSelectionSemantics(
    std::span<const proxyman::outbound::PreparedOutboundConfig> outbounds,
    std::span<const RouteRuleConfig> rules,
    std::span<const StaticInboundConfig> inbounds);

// A routing sidecar may outlive one or more removed outbounds. Those stale
// rules are unusable, but must not prevent the rest of the node from starting.
// Remove them during cold-path normalization before publishing the runtime.
[[nodiscard]] std::vector<IgnoredRouteRule> IgnoreUnknownRoutingRules(
    std::span<const proxyman::outbound::PreparedOutboundConfig> outbounds,
    std::vector<RouteRuleConfig>& rules);

[[nodiscard]] StaticInboundSemanticValidation ValidateStaticInboundSemantics(
    std::span<const StaticInboundConfig> inbounds);

}  // namespace acpp
