#pragma once

#include "infra/config_types.hpp"
#include "infra/outbound_source_config.hpp"
#include "infra/runtime_config_types.hpp"

#include <cstddef>
#include <span>
#include <string>
#include <string_view>
#include <vector>


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
    std::span<const infra::OutboundSourceConfig> outbounds,
    std::span<const RouteRuleConfig> rules,
    std::span<const StaticInboundConfig> inbounds);

[[nodiscard]] StaticInboundSemanticValidation ValidateStaticInboundSemantics(
    std::span<const StaticInboundConfig> inbounds);

