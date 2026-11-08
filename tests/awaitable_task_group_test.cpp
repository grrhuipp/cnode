#include <gtest/gtest.h>

#include "awaitable_task_group.hpp"

#include <asio/as_tuple.hpp>
#include <asio/async_result.hpp>
#include <asio/bind_cancellation_slot.hpp>
#include <asio/cancellation_signal.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/executor_work_guard.hpp>
#include <asio/post.hpp>
#include <asio/this_coro.hpp>
#include <asio/use_future.hpp>

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <new>
#include <stdexcept>
#include <thread>
#include <utility>
#include <vector>

namespace {
namespace net = ::net;
using async_allocation_test::fail_after;
using async_allocation_test::injected;

class GroupResource final : public std::pmr::memory_resource {
public:
    std::atomic<size_t> live{0};
private:
    void* do_allocate(size_t bytes, size_t alignment) override {
        async_allocation_test::Check();
        auto* result = upstream_.allocate(bytes, alignment);
        live.fetch_add(1, std::memory_order_relaxed);
        return result;
    }
    void do_deallocate(void* pointer, size_t bytes, size_t alignment) override {
        upstream_.deallocate(pointer, bytes, alignment);
        live.fetch_sub(1, std::memory_order_relaxed);
    }
    bool do_is_equal(const std::pmr::memory_resource& other) const noexcept override {
        return this == &other;
    }
    ::memory::ThreadMemoryResource upstream_;
};

void Check(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

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

void TestDynamicCancellation() {
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
    Check(counts.active == 2 && counts.finished == 1, "dynamic children must start");
    cancellation.emit(net::cancellation_type::terminal);
    io.poll();
    Check(returned == -1, "cancel must join asynchronous child cleanup");
    io.run_for(std::chrono::seconds(1));
    Check(counts.active == 0 && returned == 3 && failure, "cancel must finish every child");
    try { std::rethrow_exception(failure); }
    catch (const ::IoSystemError& error) {
        Check(error.code() == net::error::operation_aborted, "wrong cancellation error");
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

void TestExplicitCancel() {
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
    Check(result.wait_for(std::chrono::seconds(0)) == std::future_status::ready,
          "explicit stop must join all children");
    result.get();
    Check(rejected && counts.active == 0 && counts.finished == 1,
          "explicit stop must reject late spawn and preserve normal completion");
}

void TestFailure(bool start_failure) {
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
    Check(result.wait_for(std::chrono::seconds(0)) == std::future_status::ready,
          "failure must cancel and join pending children without an external wake");
    bool failed = false;
    try { result.get(); }
    catch (const OwnerFailure&) { failed = true; }
    Check(failed && counts.active == 0, "first failure must survive child cancellation");
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

void TestFailureOutranksCancellation() {
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
    Check(cleanup_finished && preserved, "cancellation masked a joined child's real failure");
}

net::awaitable<void> CancelledRequest(
    net::steady_timer& operation, net::steady_timer& cleanup, Counts& counts,
    std::unique_ptr<::transport::CancellationSource> source, bool fail_cleanup) {
    Lifetime lifetime(counts);
    auto [error] = co_await operation.async_wait(net::as_tuple(net::use_awaitable));
    Check(error == net::error::operation_aborted, "request operation was not cancelled");
    co_await net::this_coro::reset_cancellation_state(net::disable_cancellation());
    (void)co_await cleanup.async_wait(net::as_tuple(net::use_awaitable));
    // Destroy the source before the co_spawn completion callback. Its intrusive
    // subscription must detach even though the group still owns the child.
    source.reset();
    if (fail_cleanup) throw OwnerFailure{};
    throw ::IoSystemError(net::error::operation_aborted);
}

void TestRequestCancellation(bool fail_cleanup) {
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
    Check(request_counts.active == 1 && sibling_counts.active == 1,
          "request and sibling must both start");
    request_source->CancelPending();
    io.poll();
    Check(request_counts.active == 1 && sibling_counts.active == 1 &&
          result.wait_for(std::chrono::seconds(0)) != std::future_status::ready,
          "request cancellation must join cleanup without cancelling its sibling");
    cleanup.cancel();
    io.poll();
    Check(request_counts.finished == 1, "request cleanup did not complete");
    if (!fail_cleanup) {
        Check(sibling_counts.active == 1 &&
              result.wait_for(std::chrono::seconds(0)) != std::future_status::ready,
              "locally aborted request stopped its sibling or completed parent early");
        sibling.cancel();
    }
    io.restart();
    io.run();
    bool failed = false;
    try { result.get(); }
    catch (const OwnerFailure&) { failed = true; }
    Check(failed == fail_cleanup && sibling_counts.finished == 1,
          "local cancellation hid a real cleanup failure or failed to join sibling");
}

void TestStoppedRequest() {
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
    Check(counts.active == 0 && counts.finished == 0,
          "already stopped request started before its cancellation slot was bound");
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

void TestAllocationFailures() {
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
        if (borrowed_on_return || counts.active ||
            (initiation_failed ? counts.finished != 0 : returned != counts.finished)) {
            std::cerr << "allocation=" << allocation << " active=" << counts.active
                      << " finished=" << counts.finished << " returned=" << returned << '\n';
            throw std::runtime_error("failed launch must retain and join borrowed state");
        }
        if (!faulted) {
            Check(covered > 3 && partial > 0, "fault sweep must cover partial launch");
            std::cout << "allocation failures=" << covered << " partial launches=" << partial << '\n';
            return;
        }
        if (counts.finished > 0 && counts.finished < 3 && failure) ++partial;
        ++covered;
    }
    throw std::runtime_error("allocation sweep did not reach success");
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

void TestMoveOnlyStart() {
    net::io_context io;
    bool started = false;
    auto result = net::co_spawn(io, ::RunAwaitableTaskGroup(io.get_executor(),
        [value = std::make_unique<int>(42), &started](::AwaitableTaskGroup&) {
            started = *value == 42;
        }), net::use_future);
    io.run();
    result.get();
    Check(started, "a move-only start callback must not require std::function");
}

void TestExecutor() {
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
    Check(child && parent, "executor ownership must be preserved");
}

void TestIdleResidentGroup(GroupResource& resource) {
    net::io_context io;
    const auto before = resource.live.load(std::memory_order_relaxed);
    for (int i = 0; i != 1000; ++i) {
        ::ResidentTaskGroup resident(io.get_executor());
        resident.Tasks().Cancel();
    }
    Check(resource.live.load(std::memory_order_relaxed) == before,
          "resident groups without children must not allocate task state");
}

// Children started by coroutines outside the group stay owned until
// AsyncJoin, which cancels them, waits for their cleanup and closes admission;
// a per-child source cancels only its own child.
void TestResidentGroup() {
    net::io_context io;
    net::steady_timer gate(io);
    gate.expires_at(net::steady_timer::time_point::max());
    Counts counts;
    bool joined = false;
    bool rejected = false;
    {
        ::ResidentTaskGroup resident(io.get_executor());
        ::transport::CancellationSource own;
        net::co_spawn(io, [&]() -> net::awaitable<void> {
            resident.Tasks().Spawn(Wait(gate, counts, true));
            resident.Tasks().Spawn(Wait(gate, counts, true), &own);
            co_return;
        }, net::detached);
        io.poll();
        Check(counts.active == 2, "resident children must start from a foreign coroutine");
        own.Stop();
        io.run_for(std::chrono::milliseconds(100));
        Check(counts.active == 1 && counts.finished == 1,
              "a child source must cancel only its own resident child");
        net::co_spawn(io, resident.AsyncJoin(), [&](std::exception_ptr error) {
            joined = !error && counts.active == 0;
        });
        io.poll();
        Check(!joined, "resident join must wait for asynchronous child cleanup");
        io.run_for(std::chrono::milliseconds(200));
        try { resident.Tasks().Spawn(Wait(gate, counts)); }
        catch (const ::IoSystemError& error) {
            rejected = error.code() == net::error::operation_aborted;
        }
    }
    Check(joined && rejected && counts.active == 0 && counts.finished == 2,
          "resident join must cancel, join and close admission");
}
}  // namespace

void* operator new(std::size_t size) {
    async_allocation_test::Check();
    if (void* p = std::malloc(size ? size : 1)) return p;
    throw std::bad_alloc();
}
void operator delete(void* p) noexcept { std::free(p); }
void operator delete(void* p, std::size_t) noexcept { std::free(p); }

TEST(AwaitableTaskGroup, Contract) {
    GroupResource resource;
    auto* previous = std::pmr::set_default_resource(&resource);
    int result = 0;
    try {
        TestDynamicCancellation();
        TestExplicitCancel();
        TestFailure(false);
        TestFailure(true);
        TestFailureOutranksCancellation();
        TestRequestCancellation(false);
        TestRequestCancellation(true);
        TestStoppedRequest();
        TestAllocationFailures();
        TestMoveOnlyStart();
        TestExecutor();
        TestIdleResidentGroup(resource);
        TestResidentGroup();
        Check(resource.live.load() == 0, "all PMR task bookkeeping must be released");
        Check(::memory::RemoteFreeCount() == 0,
              "group and child PMR objects must be freed on the target executor");
    } catch (const std::exception& error) {
        fail_after = -1;
        std::cerr << error.what() << '\n';
        result = 1;
    }
    std::pmr::set_default_resource(previous);
    { ASSERT_EQ((result), 0); return; }
}
