#include "session_pool.hpp"

#include <asio/as_tuple.hpp>
#include <asio/cancellation_signal.hpp>
#include <asio/this_coro.hpp>

#include <chrono>
#include <cstdlib>
#include <future>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <thread>

namespace {
using async_allocation_test::fail_after;
using async_allocation_test::injected;
}
void* operator new(std::size_t size) {
    async_allocation_test::Check();
    if (void* result = std::malloc(size ? size : 1)) return result;
    throw std::bad_alloc();
}
void operator delete(void* value) noexcept { std::free(value); }
void operator delete(void* value, std::size_t) noexcept { std::free(value); }

namespace {
using namespace std::chrono_literals;
using Clock = std::chrono::steady_clock;

void Check(bool ok, const char* message) {
    if (!ok) throw std::runtime_error(message);
}

struct Session {
    const std::thread::id owner = std::this_thread::get_id();
    bool closed = false;
    size_t active_streams = 0;
    size_t close_count = 0;
    Clock::time_point closed_at{};
    acpp::net::cancellation_signal cancellation;
    int running = 0;
    bool finished = false;
    bool fail_run = false;
    acpp::ErrorCode close_error = acpp::ErrorCode::OK;

    ~Session() { if (running != 0) std::terminate(); }
    acpp::net::cancellation_slot CancellationSlot() noexcept { return cancellation.slot(); }
    acpp::net::awaitable<void> Run() {
        if (closed) co_return;
        if (fail_run) throw std::bad_alloc();
        ++running;
        acpp::net::steady_timer wait(co_await acpp::net::this_coro::executor);
        wait.expires_at(Clock::time_point::max());
        (void)co_await wait.async_wait(acpp::net::as_tuple(acpp::net::use_awaitable));
        co_await acpp::net::this_coro::reset_cancellation_state(acpp::net::disable_cancellation());
        wait.expires_after(20ms);
        co_await wait.async_wait(acpp::net::use_awaitable);
        --running;
        finished = true;
    }

    bool IsClosed() const noexcept { return closed; }
    bool Available() const noexcept { return !closed && active_streams == 0; }
    void CloseAll(acpp::ErrorCode error) noexcept {
        if (owner != std::this_thread::get_id()) std::terminate();
        if (!closed) {
            closed = true;
            close_error = error;
            closed_at = Clock::now();
            ++close_count;
            cancellation.emit(acpp::net::cancellation_type::all);
        }
    }
};
using Pool = acpp::proxy::anytls::outbound::SessionPool<Session>;

void TestPeriodicCheckWithoutRequests() {
    acpp::net::io_context io;
    auto session = std::make_shared<Session>();
    Pool pool(io, 60ms, 5ms, 0, "periodic");
    const auto start = Clock::now();
    auto lease = pool.Adopt(session);
    lease.Reuse();
    io.run_for(2s);
    Check(session->closed, "idle session required another request to expire");
    Check(session->closed_at - start >= 55ms, "check interval was ignored");
    Check(session->close_count == 1, "expired session was closed more than once");
}

void TestMinimumIdleAndBusyLease() {
    acpp::net::io_context io;
    auto first = std::make_shared<Session>();
    auto second = std::make_shared<Session>();
    auto third = std::make_shared<Session>();
    {
        Pool pool(io, 5ms, 10ms, 1, "minimum");
        auto a = pool.Adopt(first);
        auto b = pool.Adopt(second);
        auto c = pool.Adopt(third);
        a.Reuse();
        b.Reuse();
        c.Reuse();
        auto busy = pool.Acquire();
        Check(busy.Get() == third, "pool did not select most recently idle session");
        third->active_streams = 1;
        io.run_for(60ms);
        Check(first->closed && !second->closed && !third->closed,
              "minimum idle or checked-out session was not protected");
        third->active_streams = 0;
        busy.Reuse();
        io.restart();
        io.run_for(60ms);
        Check(second->closed && !third->closed, "minimum did not follow most recent return");
        auto reused = pool.Acquire();
        Check(reused.Get() == third, "minimum idle session was replaced instead of reused");
    }
    Check(third->closed, "abandoned checkout or pool retirement leaked a session");
    io.restart();
    io.run();
}

void TestCheckoutFailureAndTimerGeneration() {
    acpp::net::io_context io;
    Pool pool(io, 5ms, 5ms, 0, "generation");
    auto failed = std::make_shared<Session>();
    try {
        auto lease = pool.Adopt(failed);
        throw std::runtime_error("failure before logical-stream registration");
    } catch (const std::runtime_error&) {}
    Check(failed->closed, "exception before logical registration leaked checkout");
    // The cancelled callback from the old, now-empty pool has not run yet.
    auto replacement = std::make_shared<Session>();
    auto next = pool.Adopt(replacement);
    next.Reuse();
    io.run_for(2s);
    Check(replacement->closed, "old timer completion disabled the replacement timer");
    auto empty = pool.Acquire();
    Check(!empty.Get(), "closed session was offered for reuse");
}

void TestRetirementWithOutstandingLease() {
    acpp::net::io_context io;
    auto busy = std::make_shared<Session>();
    std::weak_ptr<Session> idle;
    Pool::Lease lease;
    {
        Pool pool(io, 1s, 1s, 1, "retired");
        lease = pool.Adopt(busy);
        auto idle_session = std::make_shared<Session>();
        idle = idle_session;
        auto returned = pool.Adopt(idle_session);
        returned.Reuse();
    }
    Check(busy->closed && !idle.expired(), "retirement must close but retain the pending physical task owner");
    lease.Reuse();
    Check(busy->close_count == 1, "return to retired pool revived or reclosed session");
    const auto start = Clock::now();
    io.run();
    Check(idle.expired(), "completed retired operation retained its session");
    Check(Clock::now() - start < 500ms, "retired pool kept periodic work alive");
}

void TestLargeIntervalDoesNotWrap() {
    acpp::net::io_context io;
    auto session = std::make_shared<Session>();
    {
        Pool pool(io, Clock::duration::max(), 1ms, 0, "large-interval");
        auto lease = pool.Adopt(session);
        lease.Reuse();
        io.run_for(10ms);
        Check(!session->closed, "large positive timer interval wrapped into an expired deadline");
    }
    io.restart();
    io.run();
    Check(session->closed, "large timer was not cancelled on retirement");
}

void TestIndependentWorkerOwnership() {
    auto run_worker = [](size_t minimum) {
        acpp::net::io_context io;
        auto session = std::make_shared<Session>();
        {
            Pool pool(io, 5ms, 5ms, minimum, "worker");
            auto lease = pool.Adopt(session);
            lease.Reuse();
            io.run_for(50ms);
            Check(session->closed == (minimum == 0), "Worker pool policy leaked across owners");
        }
        io.restart();
        io.run();
        Check(session->closed, "Worker retirement did not close retained session");
    };
    auto first = std::async(std::launch::async, run_worker, 0);
    auto second = std::async(std::launch::async, run_worker, 1);
    first.get();
    second.get();
}

void TestFailureAndRetirementCompletion() {
    acpp::net::io_context io;
    auto failed = std::make_shared<Session>();
    auto survivor = std::make_shared<Session>();
    failed->fail_run = true;
    std::weak_ptr<Session> retiring;
    {
        Pool pool(io, 1s, 1s, 1, "physical-roots");
        auto a = pool.Adopt(failed);
        auto b = pool.Adopt(survivor);
        a.Reuse();
        b.Reuse();
        io.run_for(40ms);
        Check(failed->closed && failed->close_error == acpp::ErrorCode::RESOURCE_EXHAUSTED,
              "unhandled physical task failure was discarded or lost its classification");
        Check(!survivor->closed && survivor->running == 1,
              "one physical task failure cancelled another session");
        auto checkout = pool.Acquire();
        Check(checkout.Get() == survivor, "failed physical task remained reusable");
        checkout.Reuse();
        retiring = survivor;
        survivor.reset();
    }
    Check(!retiring.expired(), "retirement destroyed an operation before asynchronous cleanup");
    io.restart();
    io.run();
    Check(retiring.expired(), "finished physical operation retained the retired pool/session");
}

void TestAdmissionFailure() {
    const auto failures_before = injected;
    size_t successful = 0;
    for (int point = 0; point != 32; ++point) {
        acpp::net::io_context io;
        auto session = std::make_shared<Session>();
        std::weak_ptr<Session> retired = session;
        {
            Pool pool(io, 1s, 1s, 1, "admission");
            fail_after = point;
            try {
                auto lease = pool.Adopt(session);
                fail_after = -1;
                ++successful;
                lease.Reuse();
            } catch (const std::bad_alloc&) {
                fail_after = -1;
                Check(session->closed, "partial physical-task admission left an open session");
            }
            io.run_for(1ms);
        }
        session.reset();
        io.restart();
        io.run();
        Check(retired.expired(), "partial launch or completed retirement retained physical task ownership");
    }
    std::cout << "physical admission faults=" << injected - failures_before
              << " successes=" << successful << " all-released=1\n";
    Check(injected - failures_before >= 4 && successful > 0,
          "admission fault matrix did not reach both failure and successful launch");
}
}  // namespace

int main() {
    try {
        TestPeriodicCheckWithoutRequests();
        TestMinimumIdleAndBusyLease();
        TestCheckoutFailureAndTimerGeneration();
        TestRetirementWithOutstandingLease();
        TestLargeIntervalDoesNotWrap();
        TestIndependentWorkerOwnership();
        TestFailureAndRetirementCompletion();
        TestAdmissionFailure();
        std::cout << "AnyTLS periodic expiry, minimum idle, leases, timer cancellation and Worker ownership passed\n";
    } catch (const std::exception& error) {
        fail_after = -1;
        std::cerr << error.what() << '\n';
        return 1;
    }
}
