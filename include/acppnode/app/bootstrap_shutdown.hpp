#pragma once

#include "acppnode/common/asio_types.hpp"

#include <asio/signal_set.hpp>

#include <memory>
#include <functional>

namespace acpp {

[[nodiscard]] std::unique_ptr<net::signal_set> InstallShutdownHandler(
    net::io_context& io_context, std::function<void()> request_stop);

}  // namespace acpp
