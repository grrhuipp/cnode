#include "async_write_gate.hpp"

#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/post.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/use_future.hpp>

#include <future>

int main() {
    acpp::net::io_context io_context;
    acpp::transport::internet::AsyncWriteGate gate(io_context);

    constexpr size_t kWaiterCount = 4;
    size_t completed_waiters = 0;
    size_t acquired_after_cancel = 0;
    bool active_acquired = false;

    auto coordinator = acpp::net::co_spawn(
        io_context,
        [&]() -> acpp::net::awaitable<void> {
            auto active = co_await gate.Acquire();
            active_acquired = static_cast<bool>(active);

            for (size_t i = 0; i < kWaiterCount; ++i) {
                acpp::net::co_spawn(
                    io_context,
                    [&]() -> acpp::net::awaitable<void> {
                        auto lease = co_await gate.Acquire();
                        if (lease) {
                            ++acquired_after_cancel;
                        }
                        ++completed_waiters;
                    },
                    acpp::net::detached);
            }

            // Queue cancellation after every spawned writer has reached the
            // busy gate. A terminal cancel must resume all four, not only one.
            co_await acpp::net::post(
                io_context, acpp::net::use_awaitable);
            gate.Cancel();
        },
        acpp::net::use_future);

    io_context.run();
    try {
        coordinator.get();
    } catch (...) {
        return 1;
    }

    if (!active_acquired) {
        return 2;
    }
    if (completed_waiters != kWaiterCount) {
        return 3;
    }
    if (acquired_after_cancel != 0) {
        return 4;
    }

    io_context.restart();
    auto after_cancel = acpp::net::co_spawn(
        io_context,
        [&]() -> acpp::net::awaitable<bool> {
            auto lease = co_await gate.Acquire();
            co_return static_cast<bool>(lease);
        },
        acpp::net::use_future);
    io_context.run();
    if (after_cancel.get()) {
        return 5;
    }

    return 0;
}
