#include "async_write_gate.hpp"

#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/post.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/use_future.hpp>

#include <future>
#include <stdexcept>
#include <utility>

int main() {
    acpp::net::io_context io_context;
    acpp::transport::internet::AsyncWriteGate gate(io_context);

    // The immediate path must be exclusive, movable, and reusable. Repeated
    // releases also leave a stale notification for the contended path below.
    for (int i = 0; i < 64; ++i) {
        auto lease = gate.TryAcquire();
        if (!lease || gate.TryAcquire()) return 6;
        auto moved = std::move(lease);
        if (lease || !moved || gate.TryAcquire()) return 7;
    }
    {
        auto held = gate.TryAcquire();
        bool resumed = false;
        auto waiter = acpp::net::co_spawn(io_context,
            [&]() -> acpp::net::awaitable<void> {
                auto lease = gate.TryAcquire();
                if (lease) throw std::runtime_error("gate admitted concurrent writer");
                lease = co_await gate.Acquire();
                if (!lease) throw std::runtime_error("gate failed to wake writer");
                resumed = true;
            }, acpp::net::use_future);
        io_context.poll();
        if (resumed) return 8;
        held.Reset();
        io_context.restart();
        io_context.run();
        waiter.get();
        if (!resumed) return 9;
        io_context.restart();
    }

    constexpr size_t kWaiterCount = 4;
    size_t completed_waiters = 0;
    size_t acquired_after_cancel = 0;
    bool active_acquired = false;

    auto coordinator = acpp::net::co_spawn(
        io_context,
        [&]() -> acpp::net::awaitable<void> {
            auto active = gate.TryAcquire();
            active_acquired = static_cast<bool>(active);

            for (size_t i = 0; i < kWaiterCount; ++i) {
                acpp::net::co_spawn(
                    io_context,
                    [&]() -> acpp::net::awaitable<void> {
                        auto lease = gate.TryAcquire();
                        if (!lease) lease = co_await gate.Acquire();
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
    if (after_cancel.get() || gate.TryAcquire()) {
        return 5;
    }

    return 0;
}
