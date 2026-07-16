#include "acppnode/transport/internet/timeout_scheduler.hpp"

#include <asio/post.hpp>

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

    acpp::TimeoutScheduler::ReleaseForIoContext(io_context);
    return 0;
}
