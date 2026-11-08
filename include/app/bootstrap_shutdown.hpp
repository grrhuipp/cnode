#pragma once

#include "common/asio_types.hpp"

#include <asio/signal_set.hpp>

#include <memory>
#include <functional>


[[nodiscard]] std::unique_ptr<net::signal_set> InstallShutdownHandler(
    net::io_context& io_context, std::function<void()> request_stop);

