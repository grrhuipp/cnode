#include "acppnode/app/bootstrap_shutdown.hpp"
#include "acppnode/infra/log.hpp"

#include <asio/signal_set.hpp>

#include <csignal>
#include <memory>

namespace acpp {

std::unique_ptr<net::signal_set> InstallShutdownHandler(
    net::io_context& io_context, std::function<void()> request_stop) {
    auto signals = std::make_unique<net::signal_set>(io_context);
    signals->add(SIGINT);
    signals->add(SIGTERM);
#ifdef _WIN32
    signals->add(SIGBREAK);
#endif

    signals->async_wait([request_stop = std::move(request_stop)](const IoErrorCode& ec, int signo) {
        if (ec) return;
        LOG_CONSOLE("shutdown signal={}", signo);
        request_stop();
    });

    return signals;
}

}  // namespace acpp
