#pragma once

#include "acppnode/app/bootstrap_runtime.hpp"

#include <atomic>
#include <memory>

namespace acpp {

[[nodiscard]] std::shared_ptr<net::signal_set> InstallShutdownHandler(
    const RuntimeContext& ctx,
    std::atomic<bool>& running);

}  // namespace acpp
