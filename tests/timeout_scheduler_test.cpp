#include "acppnode/transport/internet/timeout_scheduler.hpp"
#include "acppnode/transport/internet/async_delay.hpp"

#include <asio/co_spawn.hpp>
#include <asio/bind_cancellation_slot.hpp>
#include <asio/cancellation_signal.hpp>
#include <asio/post.hpp>
#include <asio/use_future.hpp>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <future>
#include <optional>
#include <stdexcept>
#include <thread>
#include <type_traits>
#include <vector>

namespace {

thread_local bool reject_allocations = false;
thread_local std::size_t rejected_allocations = 0;

static_assert(noexcept(std::declval<acpp::TimeoutScheduler&>().Cancel(
    std::declval<acpp::TimeoutToken&>())));
static_assert(std::is_nothrow_move_assignable_v<acpp::TimeoutToken>);

}  // namespace

void* operator new(std::size_t size) {
    if (reject_allocations) {
        ++rejected_allocations;
        throw std::bad_alloc();
    }
    if (void* pointer = std::malloc(size ? size : 1)) return pointer;
    throw std::bad_alloc();
}
void operator delete(void* pointer) noexcept { std::free(pointer); }
void operator delete(void* pointer, std::size_t) noexcept { std::free(pointer); }
void* operator new(std::size_t size, const std::nothrow_t&) noexcept {
    try { return ::operator new(size); } catch (...) { return nullptr; }
}
void operator delete(void* pointer, const std::nothrow_t&) noexcept { ::operator delete(pointer); }

namespace {

bool TestCancellationAllocation() {
    using namespace std::chrono_literals;
    acpp::net::io_context io;
    auto& scheduler = acpp::TimeoutScheduler::ForIoContext(io);
    bool cancelled_ran = false;
    bool survivor_ran = false;
    bool cancel_threw = false;
    auto cancelled = scheduler.ScheduleAfter(1ms, [&] { cancelled_ran = true; });
    auto survivor = scheduler.ScheduleAfter(10ms, [&] { survivor_ran = true; });
    const auto before = timeout_allocation_test::rejected_asio_allocations;
    timeout_allocation_test::reject_asio_allocations = true;
    try {
        scheduler.Cancel(cancelled);
    } catch (const std::bad_alloc&) {
        cancel_threw = true;
    }
    timeout_allocation_test::reject_asio_allocations = false;
    io.run_for(100ms);
    const auto allocations = timeout_allocation_test::rejected_asio_allocations - before;
    std::printf("cancel: threw=%d allocations=%zu cancelled=%d survivor=%d\n",
        cancel_threw, allocations, cancelled_ran, survivor_ran);
    return !cancel_threw && allocations == 0 && !cancelled_ran && survivor_ran;
}

bool TestDestructionAllocation() {
    using namespace std::chrono_literals;
    acpp::net::io_context io;
    auto& scheduler = acpp::TimeoutScheduler::ForIoContext(io);
    bool survivor_ran = false;
    auto abandoned = scheduler.ScheduleAfter(1ms, [] {});
    auto survivor = scheduler.ScheduleAfter(10ms, [&] { survivor_ran = true; });
    const auto before = timeout_allocation_test::rejected_asio_allocations;
    timeout_allocation_test::reject_asio_allocations = true;
    { auto retiring = std::move(abandoned); }
    timeout_allocation_test::reject_asio_allocations = false;
    io.run_for(100ms);
    const auto allocations = timeout_allocation_test::rejected_asio_allocations - before;
    std::printf("destruction: allocations=%zu survivor=%d\n", allocations, survivor_ran);
    return allocations == 0 && survivor_ran;
}

bool TestEarlierDeadlineAllocation() {
    using namespace std::chrono_literals;
    acpp::net::io_context io;
    auto& scheduler = acpp::TimeoutScheduler::ForIoContext(io);
    bool survivor_ran = false;
    bool earlier_ran = false;
    bool schedule_threw = false;
    auto survivor = scheduler.ScheduleAfter(20ms, [&] { survivor_ran = true; });
    acpp::TimeoutToken earlier;
    const auto before = timeout_allocation_test::rejected_asio_allocations;
    timeout_allocation_test::reject_asio_allocations = true;
    try {
        earlier = scheduler.ScheduleAfter(1ms, [&] { earlier_ran = true; });
    } catch (const std::bad_alloc&) {
        schedule_threw = true;
    }
    timeout_allocation_test::reject_asio_allocations = false;
    io.run_for(100ms);
    const auto allocations = timeout_allocation_test::rejected_asio_allocations - before;
    std::printf("earlier: threw=%d allocations=%zu earlier=%d survivor=%d\n",
        schedule_threw, allocations, earlier_ran, survivor_ran);
    return !schedule_threw && allocations == 0 && earlier_ran && survivor_ran;
}

bool TestFailedInitialWait() {
    using namespace std::chrono_literals;
    acpp::net::io_context io;
    auto& scheduler = acpp::TimeoutScheduler::ForIoContext(io);
    bool failed_ran = false;
    bool recovery_ran = false;
    bool failed = false;
    const auto before = timeout_allocation_test::rejected_asio_allocations;
    timeout_allocation_test::reject_asio_allocations = true;
    try {
        auto token = scheduler.ScheduleAfter(1ms, [&] { failed_ran = true; });
    } catch (const std::bad_alloc&) {
        failed = true;
    }
    timeout_allocation_test::reject_asio_allocations = false;
    auto recovery = scheduler.ScheduleAfter(1ms, [&] { recovery_ran = true; });
    io.run_for(100ms);
    const auto allocations = timeout_allocation_test::rejected_asio_allocations - before;
    std::printf("initial wait: failed=%d allocations=%zu failed_callback=%d recovery=%d\n",
        failed, allocations, failed_ran, recovery_ran);
    return failed && allocations > 0 && !failed_ran && recovery_ran;
}

bool TestCancellationStormWithoutAllocation() {
    using namespace std::chrono_literals;
    acpp::net::io_context io;
    auto& scheduler = acpp::TimeoutScheduler::ForIoContext(io);
    bool cancelled_ran = false;
    bool survivor_ran = false;
    auto keeper = scheduler.ScheduleAfter(1ms, [&] { survivor_ran = true; });
    std::vector<acpp::TimeoutToken> tokens;
    tokens.reserve(4096);
    for (std::size_t i = 0; i < 4096; ++i) {
        tokens.push_back(scheduler.ScheduleAfter(1h, [&] { cancelled_ran = true; }));
    }
    const auto before = rejected_allocations;
    const auto asio_before = timeout_allocation_test::rejected_asio_allocations;
    reject_allocations = true;
    timeout_allocation_test::reject_asio_allocations = true;
    for (auto& token : tokens) scheduler.Cancel(token);
    timeout_allocation_test::reject_asio_allocations = false;
    reject_allocations = false;
    io.run_for(100ms);
    const auto allocations = rejected_allocations - before;
    const auto asio_allocations = timeout_allocation_test::rejected_asio_allocations - asio_before;
    std::printf("cancellation storm: allocations=%zu asio_allocations=%zu cancelled=%d survivor=%d\n",
        allocations, asio_allocations, cancelled_ran, survivor_ran);
    return allocations == 0 && asio_allocations == 0 && !cancelled_ran && survivor_ran;
}

bool TestPreemptAndReplacePendingWait() {
    using namespace std::chrono_literals;
    acpp::net::io_context io;
    auto& scheduler = acpp::TimeoutScheduler::ForIoContext(io);
    auto initial = scheduler.ScheduleAfter(1h, [] {});
    const auto before = timeout_allocation_test::rejected_asio_allocations;
    bool replacement_ran = false;
    // Repeatedly cancel the last event and replace it before the cancelled
    // operation is delivered. No second underlying wait may be allocated.
    timeout_allocation_test::reject_asio_allocations = true;
    for (std::size_t i = 0; i < 200; ++i) {
        scheduler.Cancel(initial);
        initial = scheduler.ScheduleAfter(1h, [] {});
    }
    auto replacement = scheduler.ScheduleAfter(1ms, [&] { replacement_ran = true; });
    timeout_allocation_test::reject_asio_allocations = false;
    io.run_for(30ms);
    scheduler.Cancel(initial);
    io.restart();
    io.run_for(100ms);
    const auto allocations = timeout_allocation_test::rejected_asio_allocations - before;
    std::printf("pending replacement: allocations=%zu callback=%d\n", allocations, replacement_ran);
    return allocations == 0 && replacement_ran && io.stopped();
}

bool TestSleepCancellationAllocation() {
    using namespace std::chrono_literals;
    acpp::net::io_context io;
    auto& scheduler = acpp::TimeoutScheduler::ForIoContext(io);
    acpp::AsyncDelay sleep(io);
    bool survivor_ran = false;
    auto future = acpp::net::co_spawn(io, sleep.WaitFor(1h), acpp::net::use_future);
    io.poll();
    auto survivor = scheduler.ScheduleAfter(1ms, [&] { survivor_ran = true; });
    const auto before = timeout_allocation_test::rejected_asio_allocations;
    const auto ordinary_before = rejected_allocations;
    reject_allocations = true;
    timeout_allocation_test::reject_asio_allocations = true;
    sleep.Cancel();
    timeout_allocation_test::reject_asio_allocations = false;
    reject_allocations = false;
    io.run_for(100ms);
    const bool completed = future.wait_for(0ms) == std::future_status::ready;
    if (completed) future.get();
    scheduler.Cancel(survivor);
    io.restart();
    io.run_for(100ms);
    const auto allocations = timeout_allocation_test::rejected_asio_allocations - before;
    std::printf("sleep cancellation: asio_allocations=%zu allocations=%zu completed=%d survivor=%d\n",
        allocations, rejected_allocations - ordinary_before, completed, survivor_ran);
    return allocations == 0 && rejected_allocations == ordinary_before && completed && survivor_ran;
}

bool TestDelayParentCancellationAndReuse() {
    using namespace std::chrono_literals;
    acpp::net::io_context io;
    acpp::AsyncDelay delay(io);
    acpp::net::cancellation_signal cancellation;
    auto future = acpp::net::co_spawn(io, delay.WaitFor(1h),
        acpp::net::bind_cancellation_slot(cancellation.slot(), acpp::net::use_future));
    io.poll();
    cancellation.emit(acpp::net::cancellation_type::terminal);
    io.run_for(100ms);
    if (future.wait_for(0ms) != std::future_status::ready) return false;
    try {
        future.get();
    } catch (const acpp::IoSystemError& error) {
        if (error.code() != acpp::io_error::operation_aborted) return false;
    }
    io.restart();
    auto reused = acpp::net::co_spawn(io, delay.WaitFor(1ms), acpp::net::use_future);
    io.run_for(100ms);
    if (reused.wait_for(0ms) != std::future_status::ready) return false;
    reused.get();
    std::printf("parent cancellation: completed=1 reused=1\n");
    return true;
}

bool TestMaximumDelayWait() {
    using namespace std::chrono_literals;
    acpp::net::io_context io;
    acpp::AsyncDelay delay(io);
    auto future = acpp::net::co_spawn(io,
        delay.WaitFor(std::chrono::milliseconds::max()), acpp::net::use_future);
    io.run_for(10ms);
    const bool pending = future.wait_for(0ms) != std::future_status::ready;
    delay.Cancel();
    io.restart();
    io.run_for(100ms);
    if (future.wait_for(0ms) != std::future_status::ready) return false;
    future.get();
    std::printf("maximum delay wait: pending_before_cancel=%d\n", pending);
    return pending;
}

bool TestMaximumDelay() {
    using namespace std::chrono_literals;
    acpp::net::io_context io;
    auto& scheduler = acpp::TimeoutScheduler::ForIoContext(io);
    bool maximum_ran = false;
    bool immediate_ran = false;
    auto maximum = scheduler.ScheduleAfter(std::chrono::milliseconds::max(),
        [&] { maximum_ran = true; });
    auto immediate = scheduler.ScheduleAfter(-1ms, [&] { immediate_ran = true; });
    io.run_for(10ms);
    scheduler.Cancel(maximum);
    io.restart();
    io.run_for(100ms);
    std::printf("maximum delay: maximum=%d immediate=%d\n", maximum_ran, immediate_ran);
    return !maximum_ran && immediate_ran;
}

}  // namespace

int main() {
    using namespace std::chrono_literals;
    std::setvbuf(stdout, nullptr, _IONBF, 0);

    bool allocation_checks_passed = TestCancellationAllocation();
    allocation_checks_passed = TestDestructionAllocation() && allocation_checks_passed;
    allocation_checks_passed = TestEarlierDeadlineAllocation() && allocation_checks_passed;
    allocation_checks_passed = TestFailedInitialWait() && allocation_checks_passed;
    allocation_checks_passed = TestCancellationStormWithoutAllocation() && allocation_checks_passed;
    allocation_checks_passed = TestPreemptAndReplacePendingWait() && allocation_checks_passed;
    allocation_checks_passed = TestSleepCancellationAllocation() && allocation_checks_passed;
    allocation_checks_passed = TestDelayParentCancellationAndReuse() && allocation_checks_passed;
    allocation_checks_passed = TestMaximumDelayWait() && allocation_checks_passed;
    allocation_checks_passed = TestMaximumDelay() && allocation_checks_passed;
    if (!allocation_checks_passed) return 110;

    std::optional<acpp::net::io_context> recycled_io_context;
    for (size_t iteration = 0; iteration < 4; ++iteration) {
        recycled_io_context.emplace();
        bool recycled_callback_ran = false;
        {
            auto& recycled_scheduler =
                acpp::TimeoutScheduler::ForIoContext(*recycled_io_context);
            auto recycled_token = recycled_scheduler.ScheduleAfter(
                1ms, [&]() { recycled_callback_ran = true; });
            std::this_thread::sleep_for(10ms);
            recycled_io_context->run();
            recycled_scheduler.Cancel(recycled_token);
        }
        if (!recycled_callback_ran) {
            return 100;
        }
        recycled_io_context.reset();
    }

    acpp::net::io_context io_context;
    auto& scheduler = acpp::TimeoutScheduler::ForIoContext(io_context);

    bool abandoned_ran = false;
    {
        auto abandoned = scheduler.ScheduleAfter(1ms, [&]() {
            abandoned_ran = true;
        });
        if (!abandoned.Valid()) {
            return 101;
        }
    }
    std::this_thread::sleep_for(10ms);
    io_context.run();
    if (abandoned_ran) {
        return 102;
    }
    io_context.restart();

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
    acpp::AsyncDelay repeated_cancel_sleep(sleep_io_context);
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
        acpp::AsyncDelay single_wait_sleep(concurrent_sleep_io_context);
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
