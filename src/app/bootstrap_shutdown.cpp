#include "app/bootstrap_shutdown.hpp"
#include "infra/log.hpp"

#include <asio/signal_set.hpp>

#include <csignal>
#include <memory>


std::unique_ptr<net::signal_set> InstallShutdownHandler(
    net::io_context& io_context, std::function<void()> request_stop) {
    auto signals = std::make_unique<net::signal_set>(io_context);
    signals->add(SIGINT);
    signals->add(SIGTERM);

    signals->async_wait([request_stop = std::move(request_stop)](const IoErrorCode& ec, int signo) {
        if (ec) return;
        LOG_CONSOLE("Shutdown requested: signal={}", signo);
        request_stop();
    });

    return signals;
}

