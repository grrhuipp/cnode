#include "awaitable_batch.hpp"

#include <asio/as_tuple.hpp>
#include <asio/async_result.hpp>
#include <asio/bind_cancellation_slot.hpp>
#include <asio/cancellation_signal.hpp>
#include <asio/co_spawn.hpp>
#include <asio/executor_work_guard.hpp>
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

acpp::net::awaitable<void> TrackedTask(
    acpp::net::io_context& io_context,
    int& active,
    int& peak_active,
    int& completed,
    bool fail) {
    ++active;
    peak_active = std::max(peak_active, active);
    TaskScope scope{active, completed};

    acpp::net::steady_timer timer(io_context);
    timer.expires_after(std::chrono::milliseconds(10));
    (void)co_await timer.async_wait(
        acpp::net::as_tuple(acpp::net::use_awaitable));

    if (fail) {
        throw std::runtime_error("expected batch failure");
    }
}

void TestFailureBarrier() {
    acpp::net::io_context io_context;
    int active = 0;
    int peak_active = 0;
    int completed = 0;

    std::vector<acpp::net::awaitable<void>> tasks;
    tasks.push_back(TrackedTask(io_context, active, peak_active, completed, false));
    tasks.push_back(TrackedTask(io_context, active, peak_active, completed, true));
    tasks.push_back(TrackedTask(io_context, active, peak_active, completed, false));

    auto result = acpp::net::co_spawn(
        io_context,
        acpp::RunAwaitableBatch(
            io_context.get_executor(), std::move(tasks)),
        acpp::net::use_future);
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

acpp::net::awaitable<void> GatedTask(
    acpp::net::steady_timer& gate, int& active, int& completed) {
    ++active;
    TaskScope scope{active, completed};
    auto token = acpp::net::as_tuple(acpp::net::use_awaitable);
    (void)co_await acpp::net::async_initiate<decltype(token), void(acpp::IoErrorCode)>(
        [&gate](auto handler) {
            // Keep fault injection on batch launch, outside the test gate's
            // own asynchronous initiation and executor bookkeeping.
            const int saved = std::exchange(fail_after, -1);
            gate.async_wait(std::move(handler));
            fail_after = saved;
        }, token);
}

void TestCancellationBarrier() {
    acpp::net::io_context io_context;
    acpp::net::cancellation_signal cancel;
    int active = 0;
    int completed = 0;
    int completed_at_return = -1;
    std::exception_ptr failure;
    acpp::net::steady_timer gate(io_context);
    gate.expires_at(acpp::net::steady_timer::time_point::max());
    std::vector<acpp::net::awaitable<void>> tasks;
    for (int i = 0; i < 3; ++i) {
        tasks.push_back(GatedTask(gate, active, completed));
    }
    acpp::net::co_spawn(
        io_context,
        acpp::RunAwaitableBatch(io_context.get_executor(), std::move(tasks)),
        acpp::net::bind_cancellation_slot(cancel.slot(), [&](std::exception_ptr error) {
            failure = error;
            completed_at_return = completed;
        }));
    io_context.poll();
    if (active != 3) throw std::runtime_error("all children must be waiting before cancellation");
    cancel.emit(acpp::net::cancellation_type::terminal);
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
    } catch (const acpp::IoSystemError& error) {
        if (error.code() != acpp::net::error::operation_aborted) throw;
    }
}

acpp::net::awaitable<void> RunWithAllocationFailure(
    acpp::net::any_io_executor executor,
    std::vector<acpp::net::awaitable<void>> tasks, int allocation) {
    fail_after = allocation;
    try {
        co_await acpp::RunAwaitableBatch(executor, std::move(tasks));
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
        acpp::net::io_context io_context;
        int active = 0;
        int completed = 0;
        int completed_at_return = -1;
        std::exception_ptr returned_error;
        acpp::net::steady_timer gate(io_context);
        gate.expires_at(acpp::net::steady_timer::time_point::max());
        std::vector<acpp::net::awaitable<void>> tasks;
        for (int i = 0; i < 3; ++i) {
            tasks.push_back(GatedTask(gate, active, completed));
        }
        const int failures_before = injected_failures;
        acpp::net::co_spawn(io_context, RunWithAllocationFailure(
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

acpp::net::awaitable<void> ObserveExecutor(
    acpp::net::any_io_executor expected, bool& matched) {
    matched = (co_await acpp::net::this_coro::executor) == expected;
}

acpp::net::awaitable<void> CrossExecutorBatch(
    acpp::net::any_io_executor caller, acpp::net::any_io_executor worker,
    bool& child_matched, bool& caller_matched) {
    std::vector<acpp::net::awaitable<void>> tasks;
    tasks.push_back(ObserveExecutor(worker, child_matched));
    co_await acpp::RunAwaitableBatch(worker, std::move(tasks));
    caller_matched = (co_await acpp::net::this_coro::executor) == caller;
}

void TestExecutorOwnership() {
    acpp::net::io_context caller;
    acpp::net::io_context worker;
    auto guard = acpp::net::make_work_guard(worker);
    bool child_matched = false;
    bool caller_matched = false;
    auto result = acpp::net::co_spawn(caller, CrossExecutorBatch(
        caller.get_executor(), worker.get_executor(), child_matched, caller_matched),
        acpp::net::use_future);
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

int main() {
    try {
        TestFailureBarrier();
        TestCancellationBarrier();
        TestAllocationFailureBarrier();
        TestExecutorOwnership();
    } catch (const std::exception& error) {
        fail_after = -1;
        std::cerr << error.what() << '\n';
        return 1;
    }
    return 0;
}
