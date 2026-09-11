#include "awaitable_task_group.hpp"

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
#include <iostream>
#include <new>
#include <stdexcept>
#include <thread>
#include <utility>
#include <vector>

namespace {
namespace net = acpp::net;
using async_allocation_test::fail_after;
using async_allocation_test::injected;

void Check(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

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
    (void)co_await net::async_initiate<decltype(token), void(acpp::IoErrorCode)>(
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

net::awaitable<void> AddChild(acpp::AwaitableTaskGroup& group,
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
    net::co_spawn(io, acpp::RunAwaitableTaskGroup(io.get_executor(),
        [&](acpp::AwaitableTaskGroup& group) {
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
    catch (const acpp::IoSystemError& error) {
        Check(error.code() == net::error::operation_aborted, "wrong cancellation error");
    }
}

net::awaitable<void> Fail() {
    co_await net::post(net::use_awaitable);
    throw std::runtime_error("child failure");
}

net::awaitable<void> Stop(acpp::AwaitableTaskGroup& group,
                         net::steady_timer& gate, Counts& counts, bool& rejected) {
    co_await net::post(net::use_awaitable);
    group.Cancel();
    group.Cancel();
    try { group.Spawn(Wait(gate, counts)); }
    catch (const acpp::IoSystemError& error) {
        rejected = error.code() == net::error::operation_aborted;
    }
}

void TestExplicitCancel() {
    net::io_context io;
    net::steady_timer gate(io);
    gate.expires_at(net::steady_timer::time_point::max());
    Counts counts;
    bool rejected = false;
    auto result = net::co_spawn(io, acpp::RunAwaitableTaskGroup(io.get_executor(),
        [&](acpp::AwaitableTaskGroup& group) {
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
    auto result = net::co_spawn(io, acpp::RunAwaitableTaskGroup(io.get_executor(),
        [&](acpp::AwaitableTaskGroup& group) {
            group.Spawn(Wait(gate, counts, true));
            if (start_failure) throw std::runtime_error("start failure");
            group.Spawn(Fail());
        }), net::use_future);
    io.run_for(std::chrono::seconds(1));
    Check(result.wait_for(std::chrono::seconds(0)) == std::future_status::ready,
          "failure must cancel and join pending children without an external wake");
    bool failed = false;
    try { result.get(); }
    catch (const std::runtime_error& error) {
        failed = std::string(error.what()) == (start_failure ? "start failure" : "child failure");
    }
    Check(failed && counts.active == 0, "first failure must survive child cancellation");
}

net::awaitable<void> WithFailure(net::io_context& io, net::steady_timer& timer,
                                Counts& counts, int allocation) {
    std::vector<net::awaitable<void>> tasks;
    for (int i = 0; i < 3; ++i) tasks.push_back(Wait(timer, counts));
    auto start = [&](acpp::AwaitableTaskGroup& group) {
        for (auto& task : tasks) group.Spawn(std::move(task));
    };
    fail_after = allocation;
    try {
        co_await acpp::RunAwaitableTaskGroup(io.get_executor(), start);
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
    co_await acpp::RunAwaitableTaskGroup(worker, [&](acpp::AwaitableTaskGroup& group) {
        group.Spawn(Observe(worker, child));
    });
    parent = (co_await net::this_coro::executor) == caller;
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
}  // namespace

void* operator new(std::size_t size) {
    async_allocation_test::Check();
    if (void* p = std::malloc(size ? size : 1)) return p;
    throw std::bad_alloc();
}
void operator delete(void* p) noexcept { std::free(p); }
void operator delete(void* p, std::size_t) noexcept { std::free(p); }

int main() {
    try {
        TestDynamicCancellation();
        TestExplicitCancel();
        TestFailure(false);
        TestFailure(true);
        TestAllocationFailures();
        TestExecutor();
    } catch (const std::exception& error) {
        fail_after = -1;
        std::cerr << error.what() << '\n';
        return 1;
    }
}
