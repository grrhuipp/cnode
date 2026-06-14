#pragma once

#include "acppnode/app/static_inbound_prepared_config.hpp"

#include <optional>
#include <vector>

namespace acpp {

struct StaticInboundConfig;

[[nodiscard]] std::optional<StaticInboundRuntimeEntry> BuildStaticInboundRuntimeEntry(
    const StaticInboundConfig& source);

[[nodiscard]] std::vector<StaticInboundRuntimeEntry> BuildStaticInboundRuntimeEntries(
    const std::vector<StaticInboundConfig>& sources);

}  // namespace acpp
