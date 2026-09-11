#pragma once

#include "acppnode/common/asio_types.hpp"

#include <asio/signal_set.hpp>

#include <memory>

namespace acpp {

// Once runtime execution begins, active Worker state lives until process exit.
[[noreturn]] void FailRuntime(const char* phase, const char* reason) noexcept;

[[nodiscard]] std::unique_ptr<net::signal_set> InstallShutdownHandler(
    net::io_context& io_context);

}  // namespace acpp
