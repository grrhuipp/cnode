#pragma once

#include "acppnode/app/proxyman/outbound/prepared_config.hpp"
#include "acppnode/infra/outbound_source_config.hpp"

#include <optional>
#include <string_view>

namespace acpp::proxyman::outbound {

// Private cold-path registration API. Proxyman receives an already normalized
// source config and produces an immutable prepared handler constructor.
void RegisterProxy(
    std::string_view protocol,
    std::optional<PreparedOutboundCreator> (*)(
        const infra::OutboundSourceConfig& config));

[[nodiscard]] std::optional<PreparedOutboundConfig> PrepareOutboundConfig(
    const infra::OutboundSourceConfig& config);

}  // namespace acpp::proxyman::outbound
