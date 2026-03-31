#pragma once

#include "acppnode/app/bootstrap_runtime.hpp"

#include <atomic>

namespace acpp {

void StartRuntimeMonitoring(const RuntimeContext& ctx, std::atomic<bool>& running);

}  // namespace acpp
