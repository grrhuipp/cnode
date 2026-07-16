#pragma once

#include "acppnode/app/bootstrap_runtime.hpp"

#include <asio/signal_set.hpp>

#include <memory>

namespace acpp {

class RuntimeMonitor;

[[nodiscard]] std::unique_ptr<net::signal_set> InstallShutdownHandler(
    const RuntimeContext& ctx,
    RuntimeMonitor& monitor);

}  // namespace acpp
