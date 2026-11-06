#pragma once

#include "acppnode/app/prepared_inbound.hpp"

#include <vector>

namespace acpp {

struct StaticInboundConfig;

// Map every static source (plus the test inbound) to InboundSpec, validate the
// complete set, then prepare each through the shared inbound builder.
// Preparation has no UserStore or Worker side effects.
[[nodiscard]] std::vector<PreparedInbound> PrepareStartupInbounds(
    std::vector<StaticInboundConfig> sources, bool enable_test_mode);

}  // namespace acpp
