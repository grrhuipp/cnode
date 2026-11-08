#include <gtest/gtest.h>

#include "transport/internet/async_write_gate.hpp"

#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/post.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/use_future.hpp>

#include <future>
#include <stdexcept>
#include <utility>

TEST(AsyncWriteGate, Contract) {
    ::net::io_context io_context;
    ::transport::internet::AsyncWriteGate gate;

    // The immediate path must be exclusive, movable, and reusable. Repeated
    // releases also leave a stale notification for the contended path below.
    for (int i = 0; i < 64; ++i) {
        auto lease = gate.TryAcquire();
        ASSERT_FALSE((!lease || gate.TryAcquire()));
        auto moved = std::move(lease);
        ASSERT_FALSE((lease || !moved || gate.TryAcquire()));
    }
    {
        auto held = gate.TryAcquire();
        bool resumed = false;
        auto waiter = ::net::co_spawn(io_context,
            [&]() -> ::net::awaitable<void> {
                auto lease = gate.TryAcquire();
                if (lease) throw std::runtime_error("gate admitted concurrent writer");
                lease = co_await gate.Acquire();
                if (!lease) throw std::runtime_error("gate failed to wake writer");
                resumed = true;
            }, ::net::use_future);
        io_context.poll();
        ASSERT_FALSE((resumed));
        held.Reset();
        io_context.restart();
        io_context.run();
        waiter.get();
        ASSERT_FALSE((!resumed));
        io_context.restart();
    }

    constexpr size_t kWaiterCount = 4;
    size_t completed_waiters = 0;
    size_t acquired_after_cancel = 0;
    bool active_acquired = false;

    auto coordinator = ::net::co_spawn(
        io_context,
        [&]() -> ::net::awaitable<void> {
            auto active = gate.TryAcquire();
            active_acquired = static_cast<bool>(active);

            for (size_t i = 0; i < kWaiterCount; ++i) {
                ::net::co_spawn(
                    io_context,
                    [&]() -> ::net::awaitable<void> {
                        auto lease = gate.TryAcquire();
                        if (!lease) lease = co_await gate.Acquire();
                        if (lease) {
                            ++acquired_after_cancel;
                        }
                        ++completed_waiters;
                    },
                    ::net::detached);
            }

            // Queue cancellation after every spawned writer has reached the
            // busy gate. A terminal cancel must resume all four, not only one.
            co_await ::net::post(
                io_context, ::net::use_awaitable);
            gate.Cancel();
        },
        ::net::use_future);

    io_context.run();
    try {
        coordinator.get();
    } catch (...) {
        FAIL() << "asynchronous write-gate operation unexpectedly threw";
    }

    ASSERT_FALSE((!active_acquired));
    ASSERT_FALSE((completed_waiters != kWaiterCount));
    ASSERT_FALSE((acquired_after_cancel != 0));

    io_context.restart();
    auto after_cancel = ::net::co_spawn(
        io_context,
        [&]() -> ::net::awaitable<bool> {
            auto lease = co_await gate.Acquire();
            co_return static_cast<bool>(lease);
        },
        ::net::use_future);
    io_context.run();
    ASSERT_FALSE((after_cancel.get() || gate.TryAcquire()));

}
