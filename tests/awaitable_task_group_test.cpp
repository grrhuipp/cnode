#include <gtest/gtest.h>

#include "allocation_hook.hpp"
#include "common/awaitable_task_group.hpp"

#include <asio/as_tuple.hpp>
#include <asio/async_result.hpp>
#include <asio/bind_cancellation_slot.hpp>
#include <asio/cancellation_signal.hpp>
#include <asio/co_spawn.hpp>
#include <asio/executor_work_guard.hpp>
#include <asio/post.hpp>
#include <asio/this_coro.hpp>
#include <asio/use_future.hpp>

#include <chrono>
#include <cstdlib>
#include <new>
#include <stdexcept>
#include <thread>
#include <utility>
#include <vector>

namespace {
namespace net = ::net;
using async_allocation_test::fail_after;
using async_allocation_test::injected;



struct OwnerFailure final : std::runtime_error {
    OwnerFailure() : std::runtime_error("owner failure") {}
};

struct Counts {
    int active = 0;
    int finished = 0;
};

struct Lifetime {
    Counts& counts;
    explicit Lifetime(Counts& c) : counts(c) { ++counts.active; }
    ~Lifetime() { --counts.active; ++counts.finished; }
};

net::awaitable<void> Wait(net::steady_timer& timer, Counts& counts,
                          bool delay_cleanup = false) {
    Lifetime lifetime(counts);
    auto token = net::as_tuple(net::use_awaitable);
    (void)co_await net::async_initiate<decltype(token), void(::IoErrorCode)>(
        [&timer](auto handler) {
            const int saved = std::exchange(fail_after, -1);
            timer.async_wait(std::move(handler));
            fail_after = saved;
        }, token);
    if (delay_cleanup) {
        co_await net::this_coro::reset_cancellation_state(net::disable_cancellation());
        net::steady_timer cleanup(co_await net::this_coro::executor);
        cleanup.expires_after(std::chrono::milliseconds(15));
        co_await cleanup.async_wait(net::use_awaitable);
    }
}

net::awaitable<void> AddChild(::AwaitableTaskGroup& group,
                              net::steady_timer& timer, Counts& counts) {
    Lifetime lifetime(counts);
    co_await net::post(net::use_awaitable);
    group.Spawn(Wait(timer, counts, true));
}

TEST(AwaitableTaskGroup, DynamicCancellationJoinsChildCleanup) {
    net::io_context io;
    net::steady_timer gate(io);
    gate.expires_at(net::steady_timer::time_point::max());
    net::cancellation_signal cancellation;
    Counts counts;
    int returned = -1;
    std::exception_ptr failure;
    net::co_spawn(io, ::RunAwaitableTaskGroup(io.get_executor(),
        [&](::AwaitableTaskGroup& group) {
            group.Spawn(Wait(gate, counts, true));
            group.Spawn(AddChild(group, gate, counts));
        }), net::bind_cancellation_slot(cancellation.slot(),
        [&](std::exception_ptr error) {
            returned = counts.finished;
            failure = error;
        }));
    io.poll();
    EXPECT_TRUE(counts.active == 2 && counts.finished == 1) << "dynamic children must start";
    cancellation.emit(net::cancellation_type::terminal);
    io.poll();
    EXPECT_TRUE(returned == -1) << "cancel must join asynchronous child cleanup";
    io.run_for(std::chrono::seconds(1));
    const bool completed_without_external_release = counts.active == 0 && returned == 3;
    gate.cancel();
    io.restart();
    io.run();
    EXPECT_TRUE(completed_without_external_release);
    EXPECT_TRUE(counts.active == 0 && returned == 3 && failure) << "cancel must finish every child";
    ASSERT_TRUE(failure);
    try { std::rethrow_exception(failure); }
    catch (const ::IoSystemError& error) {
        EXPECT_TRUE(error.code() == net::error::operation_aborted) << "wrong cancellation error";
    }
}

net::awaitable<void> Fail() {
    co_await net::post(net::use_awaitable);
    throw OwnerFailure{};
}

net::awaitable<void> Stop(::AwaitableTaskGroup& group,
                         net::steady_timer& gate, Counts& counts, bool& rejected) {
    co_await net::post(net::use_awaitable);
    group.Cancel();
    group.Cancel();
    try { group.Spawn(Wait(gate, counts)); }
    catch (const ::IoSystemError& error) {
        rejected = error.code() == net::error::operation_aborted;
    }
}

TEST(AwaitableTaskGroup, ExplicitCancelRejectsLateSpawnAndJoinsChildren) {
    net::io_context io;
    net::steady_timer gate(io);
    gate.expires_at(net::steady_timer::time_point::max());
    Counts counts;
    bool rejected = false;
    auto result = net::co_spawn(io, ::RunAwaitableTaskGroup(io.get_executor(),
        [&](::AwaitableTaskGroup& group) {
            group.Spawn(Wait(gate, counts, true));
            group.Spawn(Stop(group, gate, counts, rejected));
        }), net::use_future);
    io.run_for(std::chrono::seconds(1));
    const bool completed_without_external_release =
        result.wait_for(std::chrono::seconds(0)) == std::future_status::ready;
    gate.cancel();
    io.restart();
    io.run();
    EXPECT_TRUE(completed_without_external_release) << "explicit stop must join all children";
    result.get();
    EXPECT_TRUE(rejected && counts.active == 0 && counts.finished == 1) << "explicit stop must reject late spawn and preserve normal completion";
}

class TaskGroupFailure : public ::testing::TestWithParam<bool> {};

TEST_P(TaskGroupFailure, CancelsAndJoinsPendingChildren) {
    const bool start_failure = GetParam();
    net::io_context io;
    net::steady_timer gate(io);
    gate.expires_at(net::steady_timer::time_point::max());
    Counts counts;
    auto result = net::co_spawn(io, ::RunAwaitableTaskGroup(io.get_executor(),
        [&](::AwaitableTaskGroup& group) {
            group.Spawn(Wait(gate, counts, true));
            if (start_failure) throw OwnerFailure{};
            group.Spawn(Fail());
        }), net::use_future);
    io.run_for(std::chrono::seconds(1));
    const bool completed_without_external_release =
        result.wait_for(std::chrono::seconds(0)) == std::future_status::ready;
    gate.cancel();
    io.restart();
    io.run();
    EXPECT_TRUE(completed_without_external_release)
        << "failure must cancel and join pending children without an external wake";
    bool failed = false;
    try { result.get(); }
    catch (const OwnerFailure&) { failed = true; }
    EXPECT_TRUE(failed && counts.active == 0) << "first failure must survive child cancellation";
}

net::awaitable<void> AbortedChild() {
    co_await net::post(net::use_awaitable);
    throw ::IoSystemError(net::error::operation_aborted);
}

net::awaitable<void> FailingCleanup(bool& finished) {
    co_await net::this_coro::reset_cancellation_state(net::disable_cancellation());
    co_await net::post(net::use_awaitable);
    co_await net::post(net::use_awaitable);
    finished = true;
    throw ::IoSystemError(net::error::address_in_use);
}

TEST(AwaitableTaskGroup, FailureOutranksCancellation) {
    net::io_context io;
    bool cleanup_finished = false;
    auto result = net::co_spawn(io, ::RunAwaitableTaskGroup(io.get_executor(),
        [&](::AwaitableTaskGroup& group) {
            group.Spawn(AbortedChild());
            group.Spawn(FailingCleanup(cleanup_finished));
        }), net::use_future);
    io.run();
    bool preserved = false;
    try { result.get(); }
    catch (const ::IoSystemError& error) {
        preserved = error.code() == net::error::address_in_use;
    }
    EXPECT_TRUE(cleanup_finished && preserved) << "cancellation masked a joined child's real failure";
}

net::awaitable<void> CancelledRequest(
    net::steady_timer& operation, net::steady_timer& cleanup, Counts& counts,
    std::unique_ptr<::transport::CancellationSource> source, bool fail_cleanup) {
    Lifetime lifetime(counts);
    auto [error] = co_await operation.async_wait(net::as_tuple(net::use_awaitable));
    EXPECT_TRUE(error == net::error::operation_aborted) << "request operation was not cancelled";
    co_await net::this_coro::reset_cancellation_state(net::disable_cancellation());
    (void)co_await cleanup.async_wait(net::as_tuple(net::use_awaitable));
    // Destroy the source before the co_spawn completion callback. Its intrusive
    // subscription must detach even though the group still owns the child.
    source.reset();
    if (fail_cleanup) throw OwnerFailure{};
    throw ::IoSystemError(net::error::operation_aborted);
}

class TaskGroupRequestCancellation : public ::testing::TestWithParam<bool> {};

TEST_P(TaskGroupRequestCancellation, JoinsCleanupAndPreservesSiblingFailureSemantics) {
    const bool fail_cleanup = GetParam();
    net::io_context io;
    net::steady_timer operation(io), cleanup(io), sibling(io);
    operation.expires_at(net::steady_timer::time_point::max());
    cleanup.expires_at(net::steady_timer::time_point::max());
    sibling.expires_at(net::steady_timer::time_point::max());
    Counts request_counts, sibling_counts;
    auto source = std::make_unique<::transport::CancellationSource>();
    auto* request_source = source.get();
    auto request = CancelledRequest(operation, cleanup, request_counts,
                                    std::move(source), fail_cleanup);
    auto result = net::co_spawn(io, ::RunAwaitableTaskGroup(io.get_executor(),
        [&](::AwaitableTaskGroup& group) {
            group.Spawn(std::move(request), request_source);
            group.Spawn(Wait(sibling, sibling_counts));
        }), net::use_future);
    io.poll();
    EXPECT_TRUE(request_counts.active == 1 && sibling_counts.active == 1) << "request and sibling must both start";
    request_source->CancelPending();
    io.poll();
    EXPECT_TRUE(request_counts.active == 1 && sibling_counts.active == 1 &&
          result.wait_for(std::chrono::seconds(0)) != std::future_status::ready) << "request cancellation must join cleanup without cancelling its sibling";
    cleanup.cancel();
    io.poll();
    EXPECT_TRUE(request_counts.finished == 1) << "request cleanup did not complete";
    if (!fail_cleanup) {
        EXPECT_TRUE(sibling_counts.active == 1 &&
              result.wait_for(std::chrono::seconds(0)) != std::future_status::ready) << "locally aborted request stopped its sibling or completed parent early";
        sibling.cancel();
    }
    io.restart();
    io.run();
    bool failed = false;
    try { result.get(); }
    catch (const OwnerFailure&) { failed = true; }
    EXPECT_TRUE(failed == fail_cleanup && sibling_counts.finished == 1) << "local cancellation hid a real cleanup failure or failed to join sibling";
}

TEST(AwaitableTaskGroup, StoppedRequestNeverStarts) {
    net::io_context io;
    net::steady_timer gate(io);
    gate.expires_at(net::steady_timer::time_point::max());
    ::transport::CancellationSource source;
    source.Stop();
    Counts counts;
    auto result = net::co_spawn(io, ::RunAwaitableTaskGroup(io.get_executor(),
        [&](::AwaitableTaskGroup& group) {
            group.Spawn(Wait(gate, counts), &source);
        }), net::use_future);
    io.run();
    result.get();
    EXPECT_TRUE(counts.active == 0 && counts.finished == 0) << "already stopped request started before its cancellation slot was bound";
}

net::awaitable<void> WithFailure(net::io_context& io, net::steady_timer& timer,
                                Counts& counts, int allocation) {
    std::vector<net::awaitable<void>> tasks;
    for (int i = 0; i < 3; ++i) tasks.push_back(Wait(timer, counts));
    auto start = [&](::AwaitableTaskGroup& group) {
        for (auto& task : tasks) group.Spawn(std::move(task));
    };
    fail_after = allocation;
    try {
        co_await ::RunAwaitableTaskGroup(io.get_executor(), start);
    } catch (...) {
        fail_after = -1;
        throw;
    }
    fail_after = -1;
}

TEST(AwaitableTaskGroup, AllocationFailuresJoinBorrowedState) {
    int covered = 0;
    int partial = 0;
    for (int allocation = 0; allocation < 128; ++allocation) {
        net::io_context io;
        net::steady_timer gate(io);
        gate.expires_at(net::steady_timer::time_point::max());
        Counts counts;
        int returned = -1;
        std::exception_ptr failure;
        const int before = injected;
        net::co_spawn(io, WithFailure(io, gate, counts, allocation),
            [&](std::exception_ptr error) {
                fail_after = -1;
                failure = error;
                returned = counts.finished;
            });
        bool initiation_failed = false;
        try { io.poll(); }
        catch (const std::bad_alloc&) { initiation_failed = true; }
        fail_after = -1;
        const bool borrowed_on_return = returned != -1 && counts.active != 0;
        const bool faulted = injected != before;
        // A failed launch must cancel its started siblings itself. Only the
        // successful sweep is released externally.
        if (!faulted) gate.cancel();
        io.restart();
        io.run_for(std::chrono::milliseconds(250));
        const bool retained_children = counts.active != 0;
        gate.cancel();
        io.restart();
        io.run();
        SCOPED_TRACE(allocation);
        EXPECT_FALSE(borrowed_on_return);
        EXPECT_FALSE(retained_children);
        EXPECT_EQ(counts.active, 0);
        EXPECT_TRUE(initiation_failed ? counts.finished == 0 : returned == counts.finished);
        if (!faulted) {
            EXPECT_GT(covered, 0);
            EXPECT_GT(partial, 0);
            return;
        }
        if (counts.finished > 0 && counts.finished < 3 && failure) ++partial;
        ++covered;
    }
    FAIL() << "allocation sweep did not reach success";
}

net::awaitable<void> Observe(net::any_io_executor expected, bool& matched) {
    matched = (co_await net::this_coro::executor) == expected;
}

net::awaitable<void> CrossExecutor(net::any_io_executor caller,
                                  net::any_io_executor worker, bool& child, bool& parent) {
    co_await ::RunAwaitableTaskGroup(worker, [&](::AwaitableTaskGroup& group) {
        group.Spawn(Observe(worker, child));
    });
    parent = (co_await net::this_coro::executor) == caller;
}

TEST(AwaitableTaskGroup, MoveOnlyStartCallbackRuns) {
    net::io_context io;
    bool started = false;
    auto result = net::co_spawn(io, ::RunAwaitableTaskGroup(io.get_executor(),
        [value = std::make_unique<int>(42), &started](::AwaitableTaskGroup&) {
            started = *value == 42;
        }), net::use_future);
    io.run();
    result.get();
    EXPECT_TRUE(started) << "a move-only start callback must not require std::function";
}

TEST(AwaitableTaskGroup, ChildAndCallerKeepTheirExecutors) {
    net::io_context caller, worker;
    auto guard = net::make_work_guard(worker);
    bool child = false, parent = false;
    auto result = net::co_spawn(caller,
        CrossExecutor(caller.get_executor(), worker.get_executor(), child, parent),
        net::use_future);
    std::thread thread([&] { worker.run(); });
    caller.run();
    guard.reset();
    thread.join();
    result.get();
    EXPECT_TRUE(child && parent) << "executor ownership must be preserved";
}


// Children started by coroutines outside the group stay owned until
// AsyncJoin, which cancels them, waits for their cleanup and closes admission;
// a per-child source cancels only its own child.
TEST(AwaitableTaskGroup, ResidentJoinCancelsChildrenAndClosesAdmission) {
    net::io_context io;
    net::steady_timer gate(io);
    gate.expires_at(net::steady_timer::time_point::max());
    Counts counts;
    bool joined = false;
    bool rejected = false;
    {
        ::ResidentTaskGroup resident(io.get_executor());
        ::transport::CancellationSource own;
        auto started = net::co_spawn(io, [&]() -> net::awaitable<void> {
            resident.Tasks().Spawn(Wait(gate, counts, true));
            resident.Tasks().Spawn(Wait(gate, counts, true), &own);
            co_return;
        }, net::use_future);
        io.poll();
        started.get();
        EXPECT_TRUE(counts.active == 2) << "resident children must start from a foreign coroutine";
        own.Stop();
        io.run_for(std::chrono::milliseconds(100));
        EXPECT_TRUE(counts.active == 1 && counts.finished == 1) << "a child source must cancel only its own resident child";
        net::co_spawn(io, resident.AsyncJoin(), [&](std::exception_ptr error) {
            joined = !error && counts.active == 0;
        });
        io.poll();
        EXPECT_TRUE(!joined) << "resident join must wait for asynchronous child cleanup";
        io.run_for(std::chrono::milliseconds(200));
        const bool completed_without_external_release = joined;
        gate.cancel();
        io.restart();
        io.run();
        EXPECT_TRUE(completed_without_external_release);
        try { resident.Tasks().Spawn(Wait(gate, counts)); }
        catch (const ::IoSystemError& error) {
            rejected = error.code() == net::error::operation_aborted;
        }
    }
    EXPECT_TRUE(joined && rejected && counts.active == 0 && counts.finished == 2) << "resident join must cancel, join and close admission";
}

void CheckAllocation(std::size_t) { async_allocation_test::Check(); }
}  // namespace

constinit allocation_hook::Hooks allocation_hook::hooks{.before_new = CheckAllocation};

INSTANTIATE_TEST_SUITE_P(ChildAndStartFailure, TaskGroupFailure, ::testing::Bool());
INSTANTIATE_TEST_SUITE_P(NormalAndFailedCleanup, TaskGroupRequestCancellation, ::testing::Bool());
