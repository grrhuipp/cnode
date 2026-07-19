#pragma once

#include "acppnode/common/asio_types.hpp"

#include <asio/signal_set.hpp>

#include <memory>

namespace acpp {

[[nodiscard]] std::unique_ptr<net::signal_set> InstallShutdownHandler(
    net::io_context& io_context);

}  // namespace acpp
