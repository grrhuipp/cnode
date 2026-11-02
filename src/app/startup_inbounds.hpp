#pragma once

#include "acppnode/app/static_inbound_prepared_config.hpp"

#include <vector>

namespace acpp {

struct StaticInboundConfig;

struct PreparedStartupInbound {
    StaticInboundRuntimeEntry runtime;
    proxyman::inbound::UserSet users;
};

// Normalize every startup source, validate the complete set, then prepare all
// protocol payloads. Preparation has no UserStore or Worker side effects.
[[nodiscard]] std::vector<PreparedStartupInbound> PrepareStartupInbounds(
    std::vector<StaticInboundConfig> sources, bool enable_test_mode);

}  // namespace acpp
