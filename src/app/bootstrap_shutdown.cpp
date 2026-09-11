#include "acppnode/app/bootstrap_shutdown.hpp"
#include "acppnode/infra/log.hpp"

#include <asio/signal_set.hpp>

#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <memory>

namespace acpp {

[[noreturn]] void FailRuntime(const char* phase, const char* reason) noexcept {
    // The asynchronous logger may itself have failed. Publish a synchronous
    // diagnostic without formatting allocations or touching live runtime state.
    std::fprintf(stderr, "runtime failed phase=%s error=%s status=forced\n", phase, reason);
    std::fflush(stderr);
    std::_Exit(EXIT_FAILURE);
}

std::unique_ptr<net::signal_set> InstallShutdownHandler(
    net::io_context& io_context) {
    auto signals = std::make_unique<net::signal_set>(io_context);
    signals->add(SIGINT);
    signals->add(SIGTERM);
#ifdef _WIN32
    signals->add(SIGBREAK);
#endif

    signals->async_wait([](const IoErrorCode& ec, int signo) {
        if (ec) {
            return;
        }
        LOG_CONSOLE("shutdown signal={} status=forced", signo);

        // Stopping is intentionally immediate: active sockets and coroutines
        // are abandoned with the process, so no runtime/static destructor may
        // re-enter Worker-local state after its owner has gone away.
        std::_Exit(EXIT_SUCCESS);
    });

    return signals;
}

}  // namespace acpp
