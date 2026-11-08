#include <gtest/gtest.h>

#include "awaitable_batch.hpp"

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
#include <iostream>
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

void TestFailureBarrier() {
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
        ::RunAwaitableBatch(
            io_context.get_executor(), std::move(tasks)),
        ::net::use_future);
    io_context.run();

    bool saw_failure = false;
    try {
        result.get();
    } catch (const std::runtime_error&) {
        saw_failure = true;
    }

    if (!saw_failure || peak_active != 3 || active != 0 || completed != 3) {
        throw std::runtime_error("a failed batch must still join every task");
    }
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

void TestFailureOutranksCancellation() {
    ::net::io_context io_context;
    bool failed_child_completed = false;
    std::vector<::net::awaitable<void>> tasks;
    tasks.push_back(OrderedFailure(true, failed_child_completed));
    tasks.push_back(OrderedFailure(false, failed_child_completed));
    auto result = ::net::co_spawn(io_context,
        ::RunAwaitableBatch(io_context.get_executor(), std::move(tasks)),
        ::net::use_future);
    io_context.run();
    ::IoErrorCode reported;
    try {
        result.get();
    } catch (const ::IoSystemError& error) {
        reported = error.code();
    }
    if (!failed_child_completed || reported != ::net::error::address_in_use) {
        throw std::runtime_error("a cancelled child must not mask a joined child's real failure");
    }
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

void TestCancellationBarrier() {
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
        ::RunAwaitableBatch(io_context.get_executor(), std::move(tasks)),
        ::net::bind_cancellation_slot(cancel.slot(), [&](std::exception_ptr error) {
            failure = error;
            completed_at_return = completed;
        }));
    io_context.poll();
    if (active != 3) throw std::runtime_error("all children must be waiting before cancellation");
    cancel.emit(::net::cancellation_type::terminal);
    io_context.poll();
    const bool returned_before_release = completed_at_return != -1;
    gate.cancel();
    io_context.run();
    if (returned_before_release || completed_at_return != 3 || active != 0 || completed != 3) {
        throw std::runtime_error("cancellation must not return while children still borrow caller state");
    }
    if (!failure) throw std::runtime_error("cancellation must be reported after joining children");
    try {
        std::rethrow_exception(failure);
    } catch (const ::IoSystemError& error) {
        if (error.code() != ::net::error::operation_aborted) throw;
    }
}

::net::awaitable<void> RunWithAllocationFailure(
    ::net::any_io_executor executor,
    std::vector<::net::awaitable<void>> tasks, int allocation) {
    fail_after = allocation;
    try {
        co_await ::RunAwaitableBatch(executor, std::move(tasks));
    } catch (...) {
        fail_after = -1;
        throw;
    }
    fail_after = -1;
}

void TestAllocationFailureBarrier() {
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
        io_context.run_for(std::chrono::milliseconds(250));
        // Asio may throw from initiation before entering the batch coroutine.
        // Such failures are safe only if no child has started at all.
        const bool failed_before_start = initiation_failed && completed == 0;
        if (returned_with_children || active != 0 ||
            (!failed_before_start && completed_at_return != completed)) {
            std::cerr << "allocation=" << allocation << " active=" << active
                      << " completed=" << completed << " returned=" << completed_at_return << '\n';
            throw std::runtime_error("allocation failure must join started children before returning");
        }
        if (injected_failures == failures_before) {
            finished_sweep = true;
            break;
        }
        if (completed > 0 && completed < 3 && returned_error) ++partial_launch_failures;
        ++covered;
    }
    if (!finished_sweep || covered == 0 || partial_launch_failures == 0) {
        throw std::runtime_error("allocation sweep must exercise failures and eventual success");
    }
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
    co_await ::RunAwaitableBatch(worker, std::move(tasks));
    caller_matched = (co_await ::net::this_coro::executor) == caller;
}

void TestExecutorOwnership() {
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
    if (!child_matched || !caller_matched) {
        throw std::runtime_error("batch tasks and caller must resume on their own executors");
    }
}

}  // namespace

void* operator new(std::size_t size) {
    if (fail_after >= 0 && fail_after-- == 0) {
        ++injected_failures;
        throw std::bad_alloc();
    }
    if (void* pointer = std::malloc(size ? size : 1)) return pointer;
    throw std::bad_alloc();
}
void operator delete(void* pointer) noexcept { std::free(pointer); }
void operator delete(void* pointer, std::size_t) noexcept { std::free(pointer); }

TEST(AwaitableBatch, Contract) {
    try {
        TestFailureBarrier();
        TestCancellationBarrier();
        TestFailureOutranksCancellation();
        TestAllocationFailureBarrier();
        TestExecutorOwnership();
    } catch (const std::exception& error) {
        fail_after = -1;
        std::cerr << error.what() << '\n';
        FAIL() << error.what();
    }
}
