#include <gtest/gtest.h>

#include "allocation_hook.hpp"
#include "common/awaitable_batch.hpp"

#include <asio/as_tuple.hpp>
#include <asio/async_result.hpp>
#include <asio/bind_cancellation_slot.hpp>
#include <asio/cancellation_signal.hpp>
#include <asio/co_spawn.hpp>
#include <asio/executor_work_guard.hpp>
#include <asio/post.hpp>
#include <asio/this_coro.hpp>
#include <asio/use_future.hpp>

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <new>
#include <stdexcept>
#include <thread>
#include <utility>
#include <vector>

namespace {

thread_local int fail_after = -1;
thread_local int injected_failures = 0;

struct TaskScope {
    int& active;
    int& completed;
    ~TaskScope() { --active; ++completed; }
};

::net::awaitable<void> TrackedTask(
    ::net::io_context& io_context,
    int& active,
    int& peak_active,
    int& completed,
    bool fail) {
    ++active;
    peak_active = std::max(peak_active, active);
    TaskScope scope{active, completed};

    ::net::steady_timer timer(io_context);
    timer.expires_after(std::chrono::milliseconds(10));
    (void)co_await timer.async_wait(
        ::net::as_tuple(::net::use_awaitable));

    if (fail) {
        throw std::runtime_error("expected batch failure");
    }
}

TEST(AwaitableBatch, FailureJoinsEveryChild) {
    ::net::io_context io_context;
    int active = 0;
    int peak_active = 0;
    int completed = 0;

    std::vector<::net::awaitable<void>> tasks;
    tasks.push_back(TrackedTask(io_context, active, peak_active, completed, false));
    tasks.push_back(TrackedTask(io_context, active, peak_active, completed, true));
    tasks.push_back(TrackedTask(io_context, active, peak_active, completed, false));

    auto result = ::net::co_spawn(
        io_context,
        ::common::RunAwaitableBatch(
            io_context.get_executor(), std::move(tasks)),
        ::net::use_future);
    io_context.run();

    bool saw_failure = false;
    try {
        result.get();
    } catch (const std::runtime_error&) {
        saw_failure = true;
    }

    EXPECT_TRUE(saw_failure);
    EXPECT_EQ(peak_active, 3);
    EXPECT_EQ(active, 0);
    EXPECT_EQ(completed, 3);
}

::net::awaitable<void> OrderedFailure(bool cancel_first, bool& completed) {
    if (cancel_first) {
        throw ::IoSystemError(::net::error::operation_aborted);
    }
    co_await ::net::post(
        co_await ::net::this_coro::executor, ::net::use_awaitable);
    completed = true;
    throw ::IoSystemError(::net::error::address_in_use);
}

TEST(AwaitableBatch, FailureOutranksCancellation) {
    ::net::io_context io_context;
    bool failed_child_completed = false;
    std::vector<::net::awaitable<void>> tasks;
    tasks.push_back(OrderedFailure(true, failed_child_completed));
    tasks.push_back(OrderedFailure(false, failed_child_completed));
    auto result = ::net::co_spawn(io_context,
        ::common::RunAwaitableBatch(io_context.get_executor(), std::move(tasks)),
        ::net::use_future);
    io_context.run();
    ::IoErrorCode reported;
    try {
        result.get();
    } catch (const ::IoSystemError& error) {
        reported = error.code();
    }
    EXPECT_TRUE(failed_child_completed);
    EXPECT_EQ(reported, ::net::error::address_in_use);
}

::net::awaitable<void> GatedTask(
    ::net::steady_timer& gate, int& active, int& completed) {
    ++active;
    TaskScope scope{active, completed};
    auto token = ::net::as_tuple(::net::use_awaitable);
    (void)co_await ::net::async_initiate<decltype(token), void(::IoErrorCode)>(
        [&gate](auto handler) {
            // Keep fault injection on batch launch, outside the test gate's
            // own asynchronous initiation and executor bookkeeping.
            const int saved = std::exchange(fail_after, -1);
            gate.async_wait(std::move(handler));
            fail_after = saved;
        }, token);
}

TEST(AwaitableBatch, CancellationJoinsEveryChild) {
    ::net::io_context io_context;
    ::net::cancellation_signal cancel;
    int active = 0;
    int completed = 0;
    int completed_at_return = -1;
    std::exception_ptr failure;
    ::net::steady_timer gate(io_context);
    gate.expires_at(::net::steady_timer::time_point::max());
    std::vector<::net::awaitable<void>> tasks;
    for (int i = 0; i < 3; ++i) {
        tasks.push_back(GatedTask(gate, active, completed));
    }
    ::net::co_spawn(
        io_context,
        ::common::RunAwaitableBatch(io_context.get_executor(), std::move(tasks)),
        ::net::bind_cancellation_slot(cancel.slot(), [&](std::exception_ptr error) {
            failure = error;
            completed_at_return = completed;
        }));
    io_context.poll();
    EXPECT_EQ(active, 3);
    cancel.emit(::net::cancellation_type::terminal);
    io_context.poll();
    const bool returned_before_release = completed_at_return != -1;
    gate.cancel();
    io_context.run();
    EXPECT_FALSE(returned_before_release);
    EXPECT_EQ(completed_at_return, 3);
    EXPECT_EQ(active, 0);
    EXPECT_EQ(completed, 3);
    ASSERT_TRUE(failure);
    try {
        std::rethrow_exception(failure);
    } catch (const ::IoSystemError& error) {
        EXPECT_EQ(error.code(), ::net::error::operation_aborted);
    }
}

::net::awaitable<void> RunWithAllocationFailure(
    ::net::any_io_executor executor,
    std::vector<::net::awaitable<void>> tasks, int allocation) {
    fail_after = allocation;
    try {
        co_await ::common::RunAwaitableBatch(executor, std::move(tasks));
    } catch (...) {
        fail_after = -1;
        throw;
    }
    fail_after = -1;
}

TEST(AwaitableBatch, AllocationFailureJoinsStartedChildren) {
    int covered = 0;
    int partial_launch_failures = 0;
    bool finished_sweep = false;
    for (int allocation = 0; allocation < 128; ++allocation) {
        ::net::io_context io_context;
        int active = 0;
        int completed = 0;
        int completed_at_return = -1;
        std::exception_ptr returned_error;
        ::net::steady_timer gate(io_context);
        gate.expires_at(::net::steady_timer::time_point::max());
        std::vector<::net::awaitable<void>> tasks;
        for (int i = 0; i < 3; ++i) {
            tasks.push_back(GatedTask(gate, active, completed));
        }
        const int failures_before = injected_failures;
        ::net::co_spawn(io_context, RunWithAllocationFailure(
            io_context.get_executor(), std::move(tasks), allocation),
            [&](std::exception_ptr error) {
                fail_after = -1;
                returned_error = error;
                completed_at_return = completed;
            });
        bool initiation_failed = false;
        try {
            io_context.poll();
        } catch (const std::bad_alloc&) {
            fail_after = -1;
            initiation_failed = true;
        }
        fail_after = -1;
        const bool returned_with_children = active != 0 && completed_at_return != -1;
        gate.cancel();
        io_context.restart();
        io_context.run();
        // Asio may throw from initiation before entering the batch coroutine.
        // Such failures are safe only if no child has started at all.
        const bool failed_before_start = initiation_failed && completed == 0;
        SCOPED_TRACE(allocation);
        EXPECT_FALSE(returned_with_children);
        EXPECT_EQ(active, 0);
        EXPECT_TRUE(failed_before_start || completed_at_return == completed);
        if (injected_failures == failures_before) {
            finished_sweep = true;
            break;
        }
        if (completed > 0 && completed < 3 && returned_error) ++partial_launch_failures;
        ++covered;
    }
    EXPECT_TRUE(finished_sweep);
    EXPECT_GT(covered, 0);
    EXPECT_GT(partial_launch_failures, 0);
}

::net::awaitable<void> ObserveExecutor(
    ::net::any_io_executor expected, bool& matched) {
    matched = (co_await ::net::this_coro::executor) == expected;
}

::net::awaitable<void> CrossExecutorBatch(
    ::net::any_io_executor caller, ::net::any_io_executor worker,
    bool& child_matched, bool& caller_matched) {
    std::vector<::net::awaitable<void>> tasks;
    tasks.push_back(ObserveExecutor(worker, child_matched));
    co_await ::common::RunAwaitableBatch(worker, std::move(tasks));
    caller_matched = (co_await ::net::this_coro::executor) == caller;
}

TEST(AwaitableBatch, ChildAndCallerKeepTheirExecutors) {
    ::net::io_context caller;
    ::net::io_context worker;
    auto guard = ::net::make_work_guard(worker);
    bool child_matched = false;
    bool caller_matched = false;
    auto result = ::net::co_spawn(caller, CrossExecutorBatch(
        caller.get_executor(), worker.get_executor(), child_matched, caller_matched),
        ::net::use_future);
    std::thread worker_thread([&] { worker.run(); });
    caller.run();
    guard.reset();
    worker_thread.join();
    result.get();
    EXPECT_TRUE(child_matched);
    EXPECT_TRUE(caller_matched);
}

void FailAfterCount(std::size_t) {
    if (fail_after >= 0 && fail_after-- == 0) {
        ++injected_failures;
        throw std::bad_alloc();
    }
}

}  // namespace

constinit allocation_hook::Hooks allocation_hook::hooks{.before_new = FailAfterCount};

