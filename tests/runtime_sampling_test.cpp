#include <gtest/gtest.h>

#include "runtime_sampling_fixture.hpp"
#include "common/allocator.hpp"
#include "proxy/inbound.hpp"

#include <asio/bind_cancellation_slot.hpp>
#include <asio/cancellation_signal.hpp>
#include <asio/executor_work_guard.hpp>
#include <thread>

namespace {
using runtime_sampling::Require;
using namespace std::chrono_literals;

TEST(RuntimeSampling, CreationFinishAndShutdownPreserveEveryTail) {
    runtime_sampling::Fixture fixture;
    fixture.Run([&]() -> net::awaitable<void> {
        constexpr size_t sessions = 8;
        for (size_t index = 0; index < sessions; ++index) {
            auto opening = net::co_spawn(fixture.io, fixture.Open(), net::use_future);
            // Collection overlaps admission, domain initialization and the real
            // authentication/dial. No private registry or snapshot is injected.
            while (opening.wait_for(0s) != std::future_status::ready) {
                const auto sample = fixture.worker.CollectRuntimeStats(false);
                EXPECT_FALSE(sample.resources.has_value());
                EXPECT_GE(sample.stats.connections_total, index);
                EXPECT_LE(sample.stats.connections_total, index + 1);
                EXPECT_LE(sample.active_connections, index + 1);
                co_await net::post(net::use_awaitable);
            }
            opening.get();
            const auto sample = fixture.worker.CollectRuntimeStats(true);
            EXPECT_TRUE(sample.resources.has_value());
            EXPECT_EQ(sample.active_connections, index + 1);
            EXPECT_EQ(sample.stats.connections_total, index + 1);
            EXPECT_EQ(sample.stats.connections_active, index + 1);
            co_await fixture.Transfer(index, 997, 509);
        }
        for (size_t index = 0; index < sessions / 2; ++index) {
            fixture.clients[index].close();
            fixture.peers[index].close();
        }
        const auto half = co_await fixture.WaitActive(sessions / 2);
        EXPECT_EQ(half.stats.connections_total, sessions);
        EXPECT_EQ(half.stats.connections_active, sessions / 2);
        // The payload is below the relay batch threshold. These bounds require
        // the retiring half's final accumulator flush to survive collection.
        EXPECT_GE(half.stats.bytes_out, (sessions / 2) * 998);
        EXPECT_GE(half.stats.bytes_in, (sessions / 2) * 510);
        EXPECT_LE(half.stats.bytes_out, sessions * 998);
        EXPECT_LE(half.stats.bytes_in, sessions * 510);
        fixture.worker.RequestStop();
        const auto stopped = co_await fixture.WaitActive(0);
        EXPECT_EQ(stopped.stats.connections_total, sessions);
        EXPECT_EQ(stopped.stats.connections_active, 0u);
        EXPECT_EQ(stopped.stats.bytes_out, sessions * 998);
        EXPECT_EQ(stopped.stats.bytes_in, sessions * 510);
        for (unsigned round = 0; round < 4; ++round) {
            const auto again = fixture.worker.CollectRuntimeStats(round % 2 == 0);
            EXPECT_EQ(again.stats.bytes_in, stopped.stats.bytes_in);
            EXPECT_EQ(again.stats.bytes_out, stopped.stats.bytes_out);
            EXPECT_EQ(again.stats.connections_total, sessions);
            EXPECT_EQ(again.stats.connections_active, 0u);
            EXPECT_EQ(again.resources.has_value(), round % 2 == 0);
        }
    });
    EXPECT_EQ(fixture.totals.Snapshot().connections_total, 8u);
    EXPECT_EQ(fixture.totals.Snapshot().bytes_out, 8u * 998);
    EXPECT_EQ(fixture.totals.Snapshot().bytes_in, 8u * 510);
}
} // namespace
