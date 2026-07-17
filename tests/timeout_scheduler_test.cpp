#include "acppnode/transport/internet/timeout_scheduler.hpp"

#include <asio/co_spawn.hpp>
#include <asio/post.hpp>
#include <asio/use_future.hpp>

#include <chrono>
#include <future>
#include <stdexcept>
#include <thread>
#include <vector>

int main() {
    using namespace std::chrono_literals;

    acpp::net::io_context io_context;
    auto& scheduler = acpp::TimeoutScheduler::ForIoContext(io_context);

    bool first_ran = false;
    bool cancelled_ran = false;
    acpp::TimeoutToken cancelled;

    auto first = scheduler.ScheduleAfter(1ms, [&]() {
        first_ran = true;
        scheduler.Cancel(cancelled);
    });
    cancelled = scheduler.ScheduleAfter(1ms, [&]() {
        cancelled_ran = true;
    });

    // Make both deadlines ready before the first timer handler collects its
    // batch. The first callback must still be able to cancel the second one.
    std::this_thread::sleep_for(10ms);
    io_context.run();

    if (!first_ran) {
        return 1;
    }
    if (cancelled_ran) {
        return 2;
    }
    if (cancelled.Valid()) {
        return 3;
    }

    scheduler.Cancel(first);

    bool after_throw_ran = false;
    auto throwing = scheduler.ScheduleAfter(1ms, []() {
        throw std::runtime_error("timeout callback failure");
    });
    auto after_throw = scheduler.ScheduleAfter(1ms, [&]() {
        after_throw_ran = true;
    });

    std::this_thread::sleep_for(10ms);
    io_context.restart();
    try {
        io_context.run();
    } catch (...) {
        return 4;
    }
    if (!after_throw_ran) {
        return 5;
    }

    scheduler.Cancel(throwing);
    scheduler.Cancel(after_throw);

    auto long_lived = scheduler.ScheduleAfter(1h, []() {});
    scheduler.Cancel(long_lived);

    io_context.restart();
    std::promise<void> run_finished;
    auto run_finished_future = run_finished.get_future();
    std::thread runner([&]() {
        io_context.run();
        run_finished.set_value();
    });
    if (run_finished_future.wait_for(1s) != std::future_status::ready) {
        io_context.stop();
        runner.join();
        acpp::TimeoutScheduler::ReleaseForIoContext(io_context);
        return 6;
    }
    runner.join();

    acpp::net::io_context left_io_context;
    acpp::net::io_context right_io_context;
    auto& left_scheduler =
        acpp::TimeoutScheduler::ForIoContext(left_io_context);
    auto& right_scheduler =
        acpp::TimeoutScheduler::ForIoContext(right_io_context);
    bool left_ran = false;
    bool right_ran = false;
    auto left_token = left_scheduler.ScheduleAfter(1ms, [&]() {
        left_ran = true;
    });
    auto right_token = right_scheduler.ScheduleAfter(1ms, [&]() {
        right_ran = true;
    });

    // Both scheduler shards start at event ID 1. Passing the other shard's
    // token must neither invalidate it nor cancel this shard's same-ID event.
    left_scheduler.Cancel(right_token);
    if (!right_token.Valid()) {
        acpp::TimeoutScheduler::ReleaseForIoContext(right_io_context);
        acpp::TimeoutScheduler::ReleaseForIoContext(left_io_context);
        acpp::TimeoutScheduler::ReleaseForIoContext(io_context);
        return 7;
    }

    std::this_thread::sleep_for(10ms);
    left_io_context.run();
    right_io_context.run();
    if (!left_ran || !right_ran) {
        acpp::TimeoutScheduler::ReleaseForIoContext(right_io_context);
        acpp::TimeoutScheduler::ReleaseForIoContext(left_io_context);
        acpp::TimeoutScheduler::ReleaseForIoContext(io_context);
        return 8;
    }

    left_scheduler.Cancel(left_token);
    right_scheduler.Cancel(right_token);
    acpp::TimeoutScheduler::ReleaseForIoContext(right_io_context);
    acpp::TimeoutScheduler::ReleaseForIoContext(left_io_context);

    acpp::net::io_context fairness_io_context;
    auto& fairness_scheduler =
        acpp::TimeoutScheduler::ForIoContext(fairness_io_context);
    constexpr size_t kTimeoutStormSize = 256;
    constexpr size_t kExpectedMaxReadyBatch = 64;
    size_t timeout_callbacks = 0;
    size_t callbacks_seen_by_post = 0;
    std::vector<acpp::TimeoutToken> storm_tokens;
    storm_tokens.reserve(kTimeoutStormSize);
    for (size_t i = 0; i < kTimeoutStormSize; ++i) {
        storm_tokens.push_back(fairness_scheduler.ScheduleAfter(1ms, [&]() {
            ++timeout_callbacks;
            if (timeout_callbacks == 1) {
                acpp::net::post(fairness_io_context, [&]() {
                    callbacks_seen_by_post = timeout_callbacks;
                });
            }
        }));
    }

    std::this_thread::sleep_for(10ms);
    fairness_io_context.run();
    if (timeout_callbacks != kTimeoutStormSize) {
        acpp::TimeoutScheduler::ReleaseForIoContext(fairness_io_context);
        acpp::TimeoutScheduler::ReleaseForIoContext(io_context);
        return 9;
    }
    if (callbacks_seen_by_post == 0 ||
        callbacks_seen_by_post > kExpectedMaxReadyBatch) {
        acpp::TimeoutScheduler::ReleaseForIoContext(fairness_io_context);
        acpp::TimeoutScheduler::ReleaseForIoContext(io_context);
        return 10;
    }
    for (auto& token : storm_tokens) {
        fairness_scheduler.Cancel(token);
    }
    acpp::TimeoutScheduler::ReleaseForIoContext(fairness_io_context);

    acpp::net::io_context cancellation_io_context;
    auto& cancellation_scheduler =
        acpp::TimeoutScheduler::ForIoContext(cancellation_io_context);
    auto keeper = cancellation_scheduler.ScheduleAfter(1h, []() {});
    constexpr size_t kCancellationStormSize = 4096;
    for (size_t i = 0; i < kCancellationStormSize; ++i) {
        auto token = cancellation_scheduler.ScheduleAfter(2h, []() {});
        cancellation_scheduler.Cancel(token);
        if (token.Valid()) {
            acpp::TimeoutScheduler::ReleaseForIoContext(
                cancellation_io_context);
            acpp::TimeoutScheduler::ReleaseForIoContext(io_context);
            return 11;
        }
    }

    bool after_cancellation_storm_ran = false;
    auto after_cancellation_storm =
        cancellation_scheduler.ScheduleAfter(1ms, [&]() {
            after_cancellation_storm_ran = true;
        });
    std::this_thread::sleep_for(10ms);
    cancellation_io_context.run_for(100ms);
    if (!after_cancellation_storm_ran) {
        acpp::TimeoutScheduler::ReleaseForIoContext(cancellation_io_context);
        acpp::TimeoutScheduler::ReleaseForIoContext(io_context);
        return 12;
    }
    cancellation_scheduler.Cancel(after_cancellation_storm);
    cancellation_scheduler.Cancel(keeper);
    acpp::TimeoutScheduler::ReleaseForIoContext(cancellation_io_context);

    acpp::net::io_context sleep_io_context;
    auto& sleep_scheduler =
        acpp::TimeoutScheduler::ForIoContext(sleep_io_context);
    acpp::ScheduledSleep repeated_cancel_sleep(sleep_io_context);
    bool second_wait_started = false;
    bool second_wait_completed = false;
    bool second_wait_completed_before_probe = false;
    auto sleep_future = acpp::net::co_spawn(
        sleep_io_context,
        [&]() -> acpp::net::awaitable<void> {
            co_await repeated_cancel_sleep.WaitFor(1h);
            second_wait_started = true;
            co_await repeated_cancel_sleep.WaitFor(1h);
            second_wait_completed = true;
        },
        acpp::net::use_future);
    acpp::net::post(sleep_io_context, [&]() {
        repeated_cancel_sleep.Cancel();
        repeated_cancel_sleep.Cancel();
    });
    auto sleep_probe = sleep_scheduler.ScheduleAfter(50ms, [&]() {
        second_wait_completed_before_probe = second_wait_completed;
        repeated_cancel_sleep.Cancel();
    });

    sleep_io_context.run();
    try {
        sleep_future.get();
    } catch (...) {
        acpp::TimeoutScheduler::ReleaseForIoContext(sleep_io_context);
        acpp::TimeoutScheduler::ReleaseForIoContext(io_context);
        return 13;
    }
    if (!second_wait_started || !second_wait_completed ||
        second_wait_completed_before_probe) {
        acpp::TimeoutScheduler::ReleaseForIoContext(sleep_io_context);
        acpp::TimeoutScheduler::ReleaseForIoContext(io_context);
        return 14;
    }
    sleep_scheduler.Cancel(sleep_probe);
    acpp::TimeoutScheduler::ReleaseForIoContext(sleep_io_context);

    acpp::net::io_context assignment_io_context;
    auto& assignment_scheduler =
        acpp::TimeoutScheduler::ForIoContext(assignment_io_context);
    bool displaced_token_ran = false;
    bool replacement_token_ran = false;
    auto assigned_token = assignment_scheduler.ScheduleAfter(1ms, [&]() {
        displaced_token_ran = true;
    });
    assigned_token = assignment_scheduler.ScheduleAfter(1ms, [&]() {
        replacement_token_ran = true;
    });
    std::this_thread::sleep_for(10ms);
    assignment_io_context.run();
    if (displaced_token_ran) {
        acpp::TimeoutScheduler::ReleaseForIoContext(assignment_io_context);
        acpp::TimeoutScheduler::ReleaseForIoContext(io_context);
        return 15;
    }
    if (!replacement_token_ran) {
        acpp::TimeoutScheduler::ReleaseForIoContext(assignment_io_context);
        acpp::TimeoutScheduler::ReleaseForIoContext(io_context);
        return 16;
    }
    assignment_scheduler.Cancel(assigned_token);
    acpp::TimeoutScheduler::ReleaseForIoContext(assignment_io_context);

    acpp::net::io_context concurrent_sleep_io_context;
    auto& concurrent_sleep_scheduler =
        acpp::TimeoutScheduler::ForIoContext(concurrent_sleep_io_context);
    bool concurrent_wait_rejected = false;
    {
        acpp::ScheduledSleep single_wait_sleep(concurrent_sleep_io_context);
        auto first_wait = acpp::net::co_spawn(
            concurrent_sleep_io_context,
            [&]() -> acpp::net::awaitable<void> {
                co_await single_wait_sleep.WaitFor(1h);
            },
            acpp::net::use_future);
        auto second_wait = acpp::net::co_spawn(
            concurrent_sleep_io_context,
            [&]() -> acpp::net::awaitable<void> {
                co_await single_wait_sleep.WaitFor(1h);
            },
            acpp::net::use_future);
        auto concurrent_sleep_probe =
            concurrent_sleep_scheduler.ScheduleAfter(20ms, [&]() {
                single_wait_sleep.Cancel();
            });

        concurrent_sleep_io_context.run_for(100ms);
        if (first_wait.wait_for(0ms) == std::future_status::ready) {
            try {
                first_wait.get();
            } catch (...) {
                acpp::TimeoutScheduler::ReleaseForIoContext(io_context);
                return 17;
            }
        }
        if (second_wait.wait_for(0ms) == std::future_status::ready) {
            try {
                second_wait.get();
            } catch (const std::logic_error&) {
                concurrent_wait_rejected = true;
            } catch (...) {
                acpp::TimeoutScheduler::ReleaseForIoContext(io_context);
                return 18;
            }
        }
        concurrent_sleep_scheduler.Cancel(concurrent_sleep_probe);
        concurrent_sleep_io_context.stop();
    }
    acpp::TimeoutScheduler::ReleaseForIoContext(concurrent_sleep_io_context);
    if (!concurrent_wait_rejected) {
        acpp::TimeoutScheduler::ReleaseForIoContext(io_context);
        return 19;
    }

    acpp::TimeoutScheduler::ReleaseForIoContext(io_context);
    return 0;
}
