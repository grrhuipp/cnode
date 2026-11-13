#include <gtest/gtest.h>

#include "allocation_hook.hpp"
#include "transport/timeout_scheduler.hpp"
#include "transport/async_delay.hpp"
#include "app/group_coordinator.hpp"
#include "app/worker.hpp"

#include <asio/co_spawn.hpp>
#include <asio/bind_cancellation_slot.hpp>
#include <asio/cancellation_signal.hpp>
#include <asio/post.hpp>
#include <asio/use_future.hpp>
#include <asio/steady_timer.hpp>
#include <asio/posix/stream_descriptor.hpp>

#include <chrono>
#include <deque>
#include <future>
#include <functional>
#include <memory>
#include <new>
#include <optional>
#include <stdexcept>
#include <thread>
#include <utility>
#include <vector>
#include <sys/eventfd.h>
#include <unistd.h>

namespace {
void FailTimeoutAllocation(std::size_t) {
    if (timeout_allocation_test::reject_allocations ||
        (timeout_allocation_test::fail_after >= 0 &&
         timeout_allocation_test::fail_after-- == 0)) {
        ++timeout_allocation_test::rejected_allocations;
        throw std::bad_alloc();
    }
}
}  // namespace

constinit allocation_hook::Hooks allocation_hook::hooks{.before_new = FailTimeoutAllocation};

namespace {
using namespace std::chrono_literals;
using timeout_allocation_test::reject_allocations;

template<class F>
struct Event final : transport::TimeoutEvent {
    explicit Event(F callback) : callback(std::move(callback)) {}
    void OnTimeout() override { callback(); }
    F callback;
};

struct CounterEvent final : transport::TimeoutEvent {
    std::size_t* counter = nullptr;
    void OnTimeout() override { if (counter) ++*counter; }
};

class TimeoutSchedulerCases : public ::testing::Test {
protected:
    void TearDown() override {
        timeout_allocation_test::reject_asio_allocations = reject_allocations = false;
        timeout_allocation_test::fail_after = -1;
        common::reject_next_process_allocation = false;
    }
};

TEST_F(TimeoutSchedulerCases, CancellationAndRearmPreserveLiveEvent) {
    net::io_context io;
    auto& scheduler = transport::TimeoutScheduler::ForIoContext(io);
    std::size_t calls = 0;
    CounterEvent event;
    event.counter = &calls;
    (void)scheduler.ScheduleAfter(1h, event);
    reject_allocations = timeout_allocation_test::reject_asio_allocations = true;
    bool detached = true;
    for (int i = 0; i != 4096; ++i) {
        scheduler.Cancel(event);
        detached = !event.Valid() && detached;
        (void)scheduler.ScheduleAfter(1h, event);
    }
    (void)scheduler.ScheduleAfter(0ms, event);
    timeout_allocation_test::reject_asio_allocations = reject_allocations = false;
    io.run();
    EXPECT_TRUE(detached);
    EXPECT_EQ(calls, 1u);
    EXPECT_FALSE(event.Valid());
}

TEST_F(TimeoutSchedulerCases, DestroyingQueuedEventCancelsItsCallback) {
    net::io_context io;
    auto& scheduler = transport::TimeoutScheduler::ForIoContext(io);
    std::size_t calls = 0;
    {
        CounterEvent abandoned;
        abandoned.counter = &calls;
        (void)scheduler.ScheduleAfter(0ms, abandoned);
    }
    io.run();
    EXPECT_EQ(calls, 0u);
    EXPECT_EQ(scheduler.GetResourceStats().active_events, 0u);
}

TEST_F(TimeoutSchedulerCases, ReentrantDestructionDoesNotHideOtherCallbackFailures) {
    net::io_context io;
    auto& scheduler = transport::TimeoutScheduler::ForIoContext(io);
    std::size_t cancelled_calls = 0, survivor_calls = 0;
    auto owner = std::make_unique<CounterEvent>();
    owner->counter = &cancelled_calls;
    Event first([&] { owner.reset(); });
    Event failure([] { throw std::runtime_error("timeout owner failed"); });
    CounterEvent survivor;
    survivor.counter = &survivor_calls;
    (void)scheduler.ScheduleAfter(0ms, first);
    (void)scheduler.ScheduleAfter(0ms, *owner);
    (void)scheduler.ScheduleAfter(0ms, failure);
    (void)scheduler.ScheduleAfter(0ms, survivor);
    bool failure_reported = false;
    try { io.run(); }
    catch (const std::runtime_error&) { failure_reported = true; }
    io.run();
    EXPECT_TRUE(failure_reported);
    EXPECT_FALSE(owner);
    EXPECT_EQ(cancelled_calls, 0u);
    EXPECT_EQ(survivor_calls, 1u);
}

TEST_F(TimeoutSchedulerCases, ExpiringEventCanDestroyItself) {
    net::io_context io;
    auto& scheduler = transport::TimeoutScheduler::ForIoContext(io);

    struct Self final : transport::TimeoutEvent {
        Self(transport::TimeoutScheduler& scheduler, std::unique_ptr<Self>& owner, bool& fired)
            : scheduler(scheduler), owner(owner), fired(fired) {}
        void OnTimeout() override {
            scheduler.Cancel(*this); // Already detached, safe even inside expiry.
            fired = true;
            owner.reset(); // No access to this event after destruction.
        }
        transport::TimeoutScheduler& scheduler;
        std::unique_ptr<Self>& owner;
        bool& fired;
    };
    bool fired = false;
    std::unique_ptr<Self> self;
    self = std::make_unique<Self>(scheduler, self, fired);
    io.restart();
    (void)scheduler.ScheduleAfter(0ms, *self);
    io.run();
    EXPECT_TRUE(fired);
    EXPECT_FALSE(self);
    EXPECT_EQ(scheduler.GetResourceStats().active_events, 0u);
}

TEST_F(TimeoutSchedulerCases, ExpiringEventCanRearmItself) {
    net::io_context io;
    auto& scheduler = transport::TimeoutScheduler::ForIoContext(io);
    struct Repeating final : transport::TimeoutEvent {
        explicit Repeating(transport::TimeoutScheduler& scheduler) : scheduler(scheduler) {}
        void OnTimeout() override {
            if (++calls < 5) (void)scheduler.ScheduleAfter(0ms, *this);
        }
        transport::TimeoutScheduler& scheduler;
        int calls = 0;
    } repeating(scheduler);
    (void)scheduler.ScheduleAfter(0ms, repeating);
    io.run();
    EXPECT_EQ(repeating.calls, 5);
    EXPECT_FALSE(repeating.Valid());
}

TEST_F(TimeoutSchedulerCases, ExpiryStormYieldsToQueuedIo) {
    net::io_context io;
    auto& scheduler = transport::TimeoutScheduler::ForIoContext(io);
    std::size_t calls = 0, observed = 0;
    const auto callback = [&] {
        if (++calls == 1) net::post(io, [&] { observed = calls; });
    };
    std::deque<Event<decltype(callback)>> storm;
    for (int i = 0; i != 256; ++i) {
        storm.emplace_back(callback);
        (void)scheduler.ScheduleAfter(0ms, storm.back());
    }
    io.run();
    // Timers must yield to queued I/O, not process the entire storm first.
    EXPECT_EQ(calls, 256u);
    EXPECT_GT(observed, 0u);
    EXPECT_LT(observed, calls);
}

TEST_F(TimeoutSchedulerCases, WaitInitiationFailureRollsBackAndAllowsRecovery) {
    net::io_context io;
    auto& scheduler = transport::TimeoutScheduler::ForIoContext(io);
    std::size_t failed_calls = 0, recovered_calls = 0;
    CounterEvent failed, recovered;
    failed.counter = &failed_calls;
    recovered.counter = &recovered_calls;
    bool rejected = false;
    common::reject_next_process_allocation = true;
    try { (void)scheduler.ScheduleAfter(1ms, failed); }
    catch (const std::bad_alloc&) { rejected = true; }
    common::reject_next_process_allocation = false;
    EXPECT_TRUE(rejected);
    EXPECT_FALSE(failed.Valid());
    (void)scheduler.ScheduleAfter(1ms, recovered);
    io.run();
    EXPECT_EQ(failed_calls, 0u);
    EXPECT_EQ(recovered_calls, 1u);
}

TEST_F(TimeoutSchedulerCases, HeapGrowthAndInterleavedCancellationPreserveSurvivingEvents) {
        net::io_context io;
        auto& scheduler = transport::TimeoutScheduler::ForIoContext(io);
        std::size_t fired = 0;
        std::deque<CounterEvent> events(12000);
        for (std::size_t i = 0; i != events.size(); ++i) {
            events[i].counter = &fired;
            (void)scheduler.ScheduleAfter(48h - std::chrono::seconds(i), events[i]);
        }
        reject_allocations = timeout_allocation_test::reject_asio_allocations = true;
        // Remove both interior and root slots; no borrowed stale entry remains.
        for (std::size_t i = 0; i < events.size(); i += 2) scheduler.Cancel(events[i]);
        for (std::size_t i = 1; i < events.size(); i += 2)
            (void)scheduler.ScheduleAfter(0ms, events[i]);
        timeout_allocation_test::reject_asio_allocations = reject_allocations = false;
        io.run();
        EXPECT_EQ(fired, events.size() / 2);
        EXPECT_EQ(scheduler.GetResourceStats().active_events, 0u);
}

TEST_F(TimeoutSchedulerCases, ReleaseInvalidatesBorrowedEventsAndRejectsNewScheduling) {
    net::io_context io;
    auto& scheduler = transport::TimeoutScheduler::ForIoContext(io);
    std::deque<CounterEvent> events(12000);
    for (auto& event : events) (void)scheduler.ScheduleAfter(1h, event);
    transport::TimeoutScheduler::ReleaseForIoContext(io);
    for (auto& event : events) EXPECT_FALSE(event.Valid());
    EXPECT_FALSE(scheduler.ScheduleAfter(0ms, events.front()));
    io.run();
}

TEST_F(TimeoutSchedulerCases, EventCannotBeCancelledOrRearmedByAnotherContext) {
    net::io_context left, right;
    auto& lhs = transport::TimeoutScheduler::ForIoContext(left);
    auto& rhs = transport::TimeoutScheduler::ForIoContext(right);
    std::size_t calls = 0;
    CounterEvent event;
    event.counter = &calls;
    (void)lhs.ScheduleAfter(0ms, event);
    rhs.Cancel(event);
    bool wrong_owner_rejected = false;
    try { (void)rhs.ScheduleAfter(0ms, event); }
    catch (const std::logic_error&) { wrong_owner_rejected = true; }
    left.run();
    EXPECT_TRUE(wrong_owner_rejected);
    EXPECT_EQ(calls, 1u);
}

TEST_F(TimeoutSchedulerCases, RecycledContextAddressDoesNotRetainSchedulerOwnership) {
    std::size_t calls = 0;
    std::optional<net::io_context> recycled;
    for (int i = 0; i != 4; ++i) {
        recycled.emplace();
        CounterEvent next;
        next.counter = &calls;
        auto& scheduler = transport::TimeoutScheduler::ForIoContext(*recycled);
        (void)scheduler.ScheduleAfter(0ms, next);
        recycled->run();
        recycled.reset();
    }
    EXPECT_EQ(calls, 4u);
}

TEST_F(TimeoutSchedulerCases, MaximumDelayCanBeExpeditedAndNegativeDelayExpiresImmediately) {
    net::io_context io;
    auto& scheduler = transport::TimeoutScheduler::ForIoContext(io);
    std::size_t far_calls = 0, immediate_calls = 0;
    CounterEvent maximum, immediate;
    maximum.counter = &far_calls;
    immediate.counter = &immediate_calls;
    (void)scheduler.ScheduleAfter(std::chrono::milliseconds::max(), maximum);
    io.poll();
    EXPECT_EQ(far_calls, 0u);
    bool expedited = false;
    reject_allocations = timeout_allocation_test::reject_asio_allocations = true;
    try { expedited = scheduler.ScheduleAfter(0ms, maximum); }
    catch (const std::bad_alloc&) {}
    timeout_allocation_test::reject_asio_allocations = reject_allocations = false;
    EXPECT_TRUE(expedited);
    (void)scheduler.ScheduleAfter(-1ms, immediate);
    io.restart();
    io.run();
    EXPECT_EQ(far_calls, 1u);
    EXPECT_EQ(immediate_calls, 1u);
}

TEST_F(TimeoutSchedulerCases, OwnerThreadDestructionDrainsSchedulerWait) {
    std::promise<bool> finished;
    auto result = finished.get_future();
    std::thread owner([&] {
        try {
            auto io = std::make_unique<net::io_context>();
            auto& scheduler = transport::TimeoutScheduler::ForIoContext(*io);
            {
                std::deque<CounterEvent> events(4096);
                for (auto& event : events) (void)scheduler.ScheduleAfter(1h, event);
            }
            transport::TimeoutScheduler::ReleaseForIoContext(*io);
            io->run();
            const bool drained = !scheduler.GetResourceStats().wait_pending;
            io.reset();
            finished.set_value(drained);
        } catch (...) { finished.set_value(false); }
    });
    owner.join();
    EXPECT_TRUE(result.get());
}

TEST_F(TimeoutSchedulerCases, DelayCancelIsIdempotentAndDoesNotCancelNextWait) {
    net::io_context io;
    transport::AsyncDelay delay(io);
    bool second_started = false, second_finished = false, early_completion = false;
    auto future = net::co_spawn(io, [&]() -> net::awaitable<void> {
        co_await delay.WaitFor(1h);
        second_started = true;
        co_await delay.WaitFor(1h);
        second_finished = true;
    }, net::use_future);
    net::post(io, [&] { delay.Cancel(); delay.Cancel(); });
    auto& scheduler = transport::TimeoutScheduler::ForIoContext(io);
    Event probe([&] { early_completion = second_finished; delay.Cancel(); });
    (void)scheduler.ScheduleAfter(10ms, probe);
    io.run();
    future.get();
    EXPECT_TRUE(second_started);
    EXPECT_TRUE(second_finished);
    EXPECT_FALSE(early_completion);
}

TEST_F(TimeoutSchedulerCases, DelayParentCancellationAllowsReuse) {
    net::io_context io;
    transport::AsyncDelay delay(io);
    net::cancellation_signal cancellation;
    bool parent_observed = false;
    auto cancelled = net::co_spawn(io, [&]() -> net::awaitable<void> {
        co_await delay.WaitFor(1h);
        parent_observed = (co_await net::this_coro::cancellation_state).cancelled() !=
            net::cancellation_type::none;
    }, net::bind_cancellation_slot(cancellation.slot(), net::use_future));
    io.poll();
    cancellation.emit(net::cancellation_type::terminal);
    io.run();
    bool aborted = false;
    try { cancelled.get(); }
    catch (const IoSystemError& error) { aborted = error.code() == io_error::operation_aborted; }
    io.restart();
    auto reused = net::co_spawn(io, delay.WaitFor(1ms), net::use_future);
    io.run();
    reused.get();
    EXPECT_TRUE(aborted || parent_observed);
}

TEST_F(TimeoutSchedulerCases, DelayRejectsConcurrentWaitAndCancelsMaximumDuration) {
    net::io_context io;
    transport::AsyncDelay delay(io);
    auto first = net::co_spawn(io, delay.WaitFor(std::chrono::milliseconds::max()), net::use_future);
    auto second = net::co_spawn(io, delay.WaitFor(1h), net::use_future);
    io.poll();
    bool rejected = false;
    try { second.get(); } catch (const std::logic_error&) { rejected = true; }
    reject_allocations = timeout_allocation_test::reject_asio_allocations = true;
    delay.Cancel();
    timeout_allocation_test::reject_asio_allocations = reject_allocations = false;
    io.run();
    first.get();
    EXPECT_TRUE(rejected);
}

TEST_F(TimeoutSchedulerCases, DelayCancellationAfterSchedulerReleaseCompletesWaiter) {
    net::io_context io;
    transport::AsyncDelay delay(io);
    auto waiting = net::co_spawn(io, delay.WaitFor(1h), net::use_future);
    io.poll();
    transport::TimeoutScheduler::ReleaseForIoContext(io);
    delay.Cancel();
    io.restart();
    io.run_for(100ms);
    ASSERT_EQ(waiting.wait_for(0ms), std::future_status::ready);
    waiting.get();
}


}  // namespace

