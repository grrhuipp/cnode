#include <gtest/gtest.h>
#include "transport/async_write_gate.hpp"
#include <asio/co_spawn.hpp>
#include <asio/post.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/use_future.hpp>
#include <array>
#include <future>
#include <utility>

TEST(AsyncWriteGate, MovedLeaseRetainsExclusiveOwnershipAndReleaseAllowsReuse) {
    ::transport::AsyncWriteGate gate;
    for (int i = 0; i < 64; ++i) {
        auto lease = gate.TryAcquire();
        ASSERT_TRUE(lease);
        EXPECT_FALSE(gate.TryAcquire());
        auto moved = std::move(lease);
        EXPECT_FALSE(lease);
        EXPECT_TRUE(moved);
        EXPECT_FALSE(gate.TryAcquire());
    }
}

TEST(AsyncWriteGate, ContendedWriterWaitsForReleaseDespiteStaleNotifications) {
    ::net::io_context io;
    ::transport::AsyncWriteGate gate;
    for (int i = 0; i < 64; ++i) { auto lease = gate.TryAcquire(); }
    auto held = gate.TryAcquire();
    bool resumed = false;
    auto waiter = ::net::co_spawn(io, [&]() -> ::net::awaitable<void> {
        auto lease = gate.TryAcquire();
        EXPECT_FALSE(lease);
        if (!lease) lease = co_await gate.Acquire();
        EXPECT_TRUE(lease);
        resumed = static_cast<bool>(lease);
    }, ::net::use_future);
    io.poll();
    EXPECT_FALSE(resumed);
    held.Reset();
    io.restart();
    io.run();
    waiter.get();
    EXPECT_TRUE(resumed);
}

TEST(AsyncWriteGate, CancellationJoinsAllWaitersAndPermanentlyClosesAdmission) {
    ::net::io_context io;
    ::transport::AsyncWriteGate gate;
    constexpr size_t count = 4;
    std::array<std::future<bool>, count> waiters;
    auto held = gate.TryAcquire();
    ASSERT_TRUE(held);
    for (auto& waiter : waiters)
        waiter = ::net::co_spawn(io, [&]() -> ::net::awaitable<bool> {
            auto lease = co_await gate.Acquire();
            co_return static_cast<bool>(lease);
        }, ::net::use_future);
    io.poll();
    for (auto& waiter : waiters)
        EXPECT_NE(waiter.wait_for(std::chrono::seconds(0)), std::future_status::ready);
    gate.Cancel();
    held.Reset();
    io.restart();
    io.run();
    for (auto& waiter : waiters) EXPECT_FALSE(waiter.get());
    io.restart();
    auto after_cancel = ::net::co_spawn(io, [&]() -> ::net::awaitable<bool> {
        auto lease = co_await gate.Acquire();
        co_return static_cast<bool>(lease);
    }, ::net::use_future);
    io.run();
    EXPECT_FALSE(after_cancel.get());
    EXPECT_FALSE(gate.TryAcquire());
}
