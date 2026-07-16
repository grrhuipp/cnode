#pragma once

#include "acppnode/app/proxyman/outbound/prepared_config.hpp"
#include "acppnode/infra/runtime_config_types.hpp"

#include <cstddef>
#include <span>
#include <string_view>

namespace acpp {

enum class ConfigSemanticError {
    None,
    NoOutbounds,
    EmptyOutboundTag,
    DuplicateOutboundTag,
    EmptyRouteOutboundTag,
    UnknownRouteOutboundTag,
};

struct ConfigSemanticValidation {
    ConfigSemanticError error = ConfigSemanticError::None;
    size_t index = 0;
    std::string_view tag;

    [[nodiscard]] bool Ok() const noexcept {
        return error == ConfigSemanticError::None;
    }
};

[[nodiscard]] ConfigSemanticValidation ValidateOutboundRoutingSemantics(
    std::span<const proxyman::outbound::PreparedOutboundConfig> outbounds,
    std::span<const RouteRuleConfig> rules);

}  // namespace acpp
