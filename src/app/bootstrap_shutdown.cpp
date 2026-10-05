#include "acppnode/app/bootstrap_shutdown.hpp"

#include <asio/as_tuple.hpp>
#include <asio/signal_set.hpp>
#include <asio/use_awaitable.hpp>

#include <csignal>

namespace acpp {

net::awaitable<int> WaitForShutdownSignal(net::any_io_executor executor) {
    net::signal_set signals(std::move(executor));
    signals.add(SIGINT);
    signals.add(SIGTERM);
#ifdef _WIN32
    signals.add(SIGBREAK);
#endif

    auto [error, signal] =
        co_await signals.async_wait(net::as_tuple(net::use_awaitable));
    if (error) throw IoSystemError(error);
    co_return signal;
}

}  // namespace acpp
