#include <gtest/gtest.h>

#include "transport/internet/timeout_scheduler.hpp"
#include "transport/internet/async_delay.hpp"
#include "app/session_group_executor.hpp"
#include "../src/app/worker_memory_reclaimer.hpp"

#include <asio/co_spawn.hpp>
#include <asio/bind_cancellation_slot.hpp>
#include <asio/cancellation_signal.hpp>
#include <asio/post.hpp>
#include <asio/use_future.hpp>
#include <asio/steady_timer.hpp>
#include <asio/posix/stream_descriptor.hpp>

#include <chrono>
#include <cstdio>
#include <deque>
#include <future>
#include <functional>
#include <memory>
#include <optional>
#include <stdexcept>
#include <thread>
#include <utility>
#include <vector>
#include <sys/eventfd.h>
#include <unistd.h>

namespace {
using namespace std::chrono_literals;
using timeout_allocation_test::reject_allocations;
using timeout_allocation_test::rejected_allocations;

template<class F>
struct Event final : TimeoutEvent {
    explicit Event(F callback) : callback(std::move(callback)) {}
    void OnTimeout() override { callback(); }
    F callback;
};

struct CounterEvent final : TimeoutEvent {
    std::size_t* counter = nullptr;
    void OnTimeout() override { if (counter) ++*counter; }
};

struct ResourceScope {
    memory::ThreadMemoryResource resource;
    std::pmr::memory_resource* previous = std::pmr::set_default_resource(&resource);
    ~ResourceScope() { std::pmr::set_default_resource(previous); }
};

bool TestCancellationAndRearm() {
    net::io_context io;
    auto& scheduler = TimeoutScheduler::ForIoContext(io);
    std::size_t calls = 0, abandoned_calls = 0;
    CounterEvent event;
    event.counter = &calls;
    (void)scheduler.ScheduleAfter(1h, event);
    const auto ordinary_before = rejected_allocations;
    const auto asio_before = timeout_allocation_test::rejected_asio_allocations;
    reject_allocations = timeout_allocation_test::reject_asio_allocations = true;
    for (int i = 0; i != 4096; ++i) {
        scheduler.Cancel(event);
        if (event.Valid()) return false;
        (void)scheduler.ScheduleAfter(1h, event);
    }
    (void)scheduler.ScheduleAfter(0ms, event);
    {
        CounterEvent abandoned;
        abandoned.counter = &abandoned_calls;
        (void)scheduler.ScheduleAfter(0ms, abandoned);
    }
    timeout_allocation_test::reject_asio_allocations = reject_allocations = false;
    io.run();
    return calls == 1 && abandoned_calls == 0 && !event.Valid() &&
        rejected_allocations == ordinary_before &&
        timeout_allocation_test::rejected_asio_allocations == asio_before;
}

bool TestReentrantDestructionAndExceptions() {
    net::io_context io;
    auto& scheduler = TimeoutScheduler::ForIoContext(io);
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
    if (!failure_reported || owner || cancelled_calls || survivor_calls != 1) return false;

    struct Self final : TimeoutEvent {
        Self(TimeoutScheduler& scheduler, std::unique_ptr<Self>& owner, bool& fired)
            : scheduler(scheduler), owner(owner), fired(fired) {}
        void OnTimeout() override {
            scheduler.Cancel(*this); // Already detached, safe even inside expiry.
            fired = true;
            owner.reset(); // No access to this event after destruction.
        }
        TimeoutScheduler& scheduler;
        std::unique_ptr<Self>& owner;
        bool& fired;
    };
    bool fired = false;
    std::unique_ptr<Self> self;
    self = std::make_unique<Self>(scheduler, self, fired);
    io.restart();
    (void)scheduler.ScheduleAfter(0ms, *self);
    io.run();
    return fired && !self && scheduler.GetResourceStats().active_events == 0;
}

bool TestSelfRearmAndFairness() {
    net::io_context io;
    auto& scheduler = TimeoutScheduler::ForIoContext(io);
    struct Repeating final : TimeoutEvent {
        explicit Repeating(TimeoutScheduler& scheduler) : scheduler(scheduler) {}
        void OnTimeout() override {
            if (++calls < 5) (void)scheduler.ScheduleAfter(0ms, *this);
        }
        TimeoutScheduler& scheduler;
        int calls = 0;
    } repeating(scheduler);
    (void)scheduler.ScheduleAfter(0ms, repeating);
    io.run();
    if (repeating.calls != 5 || repeating.Valid()) return false;

    io.restart();
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
    return calls == 256 && observed > 0 && observed < calls;
}

bool TestWaitInitiationFailureAndRecovery() {
    net::io_context io;
    auto& scheduler = TimeoutScheduler::ForIoContext(io);
    std::size_t failed_calls = 0, recovered_calls = 0;
    CounterEvent failed, recovered;
    failed.counter = &failed_calls;
    recovered.counter = &recovered_calls;
    bool rejected = false;
    const auto before = memory::rejected_process_allocations;
    memory::reject_next_process_allocation = true;
    try { (void)scheduler.ScheduleAfter(1ms, failed); }
    catch (const std::bad_alloc&) { rejected = true; }
    memory::reject_next_process_allocation = false;
    if (!rejected || failed.Valid() ||
        memory::rejected_process_allocations != before + 1) return false;
    (void)scheduler.ScheduleAfter(1ms, recovered);
    io.run();
    return failed_calls == 0 && recovered_calls == 1;
}

bool TestHeapGrowthAndReentrantMaintenance() {
    ResourceScope resource;
    auto& pool = memory::ThreadMemoryPool();
    pool.PurgeIdle();
    bool passed = false;
    {
        net::io_context io;
        auto& scheduler = TimeoutScheduler::ForIoContext(io);
        WorkerMemoryReclaimer reclaimer;
        reclaimer.Start(scheduler);
        std::size_t fired = 0;
        std::deque<CounterEvent> events(12000);
        for (std::size_t i = 0; i != events.size(); ++i) {
            events[i].counter = &fired;
            pool.PurgeIdle();
            (void)scheduler.ScheduleAfter(48h - std::chrono::seconds(i), events[i]);
        }
        const auto before = rejected_allocations;
        const auto asio_before = timeout_allocation_test::rejected_asio_allocations;
        reject_allocations = timeout_allocation_test::reject_asio_allocations = true;
        // Remove both interior and root slots; no borrowed stale entry remains.
        for (std::size_t i = 0; i < events.size(); i += 2) scheduler.Cancel(events[i]);
        for (std::size_t i = 1; i < events.size(); i += 2)
            (void)scheduler.ScheduleAfter(0ms, events[i]);
        timeout_allocation_test::reject_asio_allocations = reject_allocations = false;
        io.run();
        passed = fired == events.size() / 2 && rejected_allocations == before &&
            timeout_allocation_test::rejected_asio_allocations == asio_before &&
            scheduler.GetResourceStats().active_events == 0;
        // Release invalidates borrowed events before their owners are destroyed.
        for (auto& event : events) (void)scheduler.ScheduleAfter(1h, event);
        TimeoutScheduler::ReleaseForIoContext(io);
        for (auto& event : events) passed = passed && !event.Valid();
        passed = passed && !scheduler.ScheduleAfter(0ms, events.front());
        io.restart();
        io.run();
    }
    pool.PurgeIdle();
    return passed && pool.GetFootprint().mapped_bytes == 0;
}

bool TestShardAndRecycledContextOwnership() {
    net::io_context left, right;
    auto& lhs = TimeoutScheduler::ForIoContext(left);
    auto& rhs = TimeoutScheduler::ForIoContext(right);
    std::size_t calls = 0;
    CounterEvent event;
    event.counter = &calls;
    (void)lhs.ScheduleAfter(0ms, event);
    rhs.Cancel(event);
    bool wrong_owner_rejected = false;
    try { (void)rhs.ScheduleAfter(0ms, event); }
    catch (const std::logic_error&) { wrong_owner_rejected = true; }
    left.run();
    if (!wrong_owner_rejected || calls != 1) return false;
    std::optional<net::io_context> recycled;
    for (int i = 0; i != 4; ++i) {
        recycled.emplace();
        CounterEvent next;
        next.counter = &calls;
        auto& scheduler = TimeoutScheduler::ForIoContext(*recycled);
        (void)scheduler.ScheduleAfter(0ms, next);
        recycled->run();
        recycled.reset();
    }
    return calls == 5;
}

bool TestMaximumDelay() {
    net::io_context io;
    auto& scheduler = TimeoutScheduler::ForIoContext(io);
    std::size_t far_calls = 0, immediate_calls = 0;
    CounterEvent maximum, immediate;
    maximum.counter = &far_calls;
    immediate.counter = &immediate_calls;
    (void)scheduler.ScheduleAfter(std::chrono::milliseconds::max(), maximum);
    io.poll();
    if (far_calls != 0) return false;
    const auto ordinary_before = rejected_allocations;
    const auto asio_before = timeout_allocation_test::rejected_asio_allocations;
    bool expedited = false;
    reject_allocations = timeout_allocation_test::reject_asio_allocations = true;
    try { expedited = scheduler.ScheduleAfter(0ms, maximum); }
    catch (const std::bad_alloc&) {}
    timeout_allocation_test::reject_asio_allocations = reject_allocations = false;
    if (!expedited) return false;
    (void)scheduler.ScheduleAfter(-1ms, immediate);
    io.restart();
    io.run();
    return far_calls == 1 && immediate_calls == 1 &&
        rejected_allocations == ordinary_before &&
        timeout_allocation_test::rejected_asio_allocations == asio_before;
}

bool TestPoolMaintenance() {
    net::io_context io;
    auto& scheduler = TimeoutScheduler::ForIoContext(io);
    auto& pool = memory::ThreadMemoryPool();
    pool.PurgeIdle();
    WorkerMemoryReclaimer reclaimer;
    reclaimer.Start(scheduler);
    std::vector<void*> buffers;
    for (int i = 0; i < 12; ++i) {
        auto* p = memory::AllocatePmr(8192, 16);
        if (!p) return false;
        buffers.push_back(p);
    }
    auto* held = buffers.back();
    *static_cast<unsigned char*>(held) = 0xA5;
    for (auto* p : buffers) if (p != held) memory::DeallocatePmr(p);
    bool idle_returned = false;
    Event probe([&] {
        idle_returned = pool.GetFootprint().idle_bytes == 0 &&
            *static_cast<unsigned char*>(held) == 0xA5;
        memory::DeallocatePmr(held);
    });
    (void)scheduler.ScheduleAfter(50ms, probe);
    io.run();
    if (!idle_returned || pool.GetFootprint().idle_bytes != 0) return false;

    io.restart();
    auto* p = memory::AllocatePmr(8192, 8);
    memory::DeallocatePmr(p);
    p = memory::AllocatePmr(8192, 16);
    *static_cast<unsigned char*>(p) = 0x5A;
    bool reused_survived = false;
    Event reuse_probe([&] {
        reused_survived = pool.GetFootprint().idle_bytes == 0 &&
            *static_cast<unsigned char*>(p) == 0x5A;
        memory::DeallocatePmr(p);
    });
    (void)scheduler.ScheduleAfter(30ms, reuse_probe);
    io.run();
    if (!reused_survived || pool.GetFootprint().idle_bytes != 0) return false;

    io.restart();
    p = memory::AllocatePmr(8192, 16);
    const auto before = memory::rejected_process_allocations;
    memory::reject_next_process_allocation = true;
    memory::DeallocatePmr(p);
    memory::reject_next_process_allocation = false;
    if (memory::rejected_process_allocations != before + 1 ||
        pool.GetFootprint().idle_bytes) return false;
    p = memory::AllocatePmr(8192, 16);
    memory::DeallocatePmr(p);
    io.run();
    if (pool.GetFootprint().idle_bytes) return false;
    TimeoutScheduler::ReleaseForIoContext(io);
    p = memory::AllocatePmr(8192, 16);
    memory::DeallocatePmr(p);
    return pool.GetFootprint().idle_bytes == 0;
}

bool TestMaintenanceIsolation() {
    struct Maintenance final : TimeoutMaintenance {
        void OnMaintenance() noexcept override { ++calls; }
        int calls = 0;
    } first, other;
    net::io_context io;
    auto& scheduler = TimeoutScheduler::ForIoContext(io);
    (void)scheduler.SetMaintenanceDeadline(first, std::chrono::steady_clock::now() + 5ms);
    bool conflict = false;
    try { (void)scheduler.SetMaintenanceDeadline(other, std::chrono::steady_clock::now()); }
    catch (const std::logic_error&) { conflict = true; }
    scheduler.CancelMaintenance(other);
    CounterEvent cancelled;
    (void)scheduler.ScheduleAfter(1ms, cancelled);
    scheduler.Cancel(cancelled);
    io.run();
    if (!conflict || first.calls != 1 || other.calls != 0) return false;
    io.restart();
    (void)scheduler.SetMaintenanceDeadline(first, std::chrono::steady_clock::now() + 1h);
    const auto before = timeout_allocation_test::rejected_asio_allocations;
    timeout_allocation_test::reject_asio_allocations = reject_allocations = true;
    scheduler.CancelMaintenance(first);
    timeout_allocation_test::reject_asio_allocations = reject_allocations = false;
    io.run();
    return first.calls == 1 && timeout_allocation_test::rejected_asio_allocations == before;
}

bool TestOwnerThreadServiceDestruction() {
    ResourceScope resource;
    std::promise<bool> finished;
    auto result = finished.get_future();
    std::thread owner([&] {
        try {
            auto io = std::make_unique<net::io_context>();
            auto& scheduler = TimeoutScheduler::ForIoContext(*io);
            {
                std::deque<CounterEvent> events(4096);
                for (auto& event : events) (void)scheduler.ScheduleAfter(1h, event);
            }
            TimeoutScheduler::ReleaseForIoContext(*io);
            io->run();
            const bool drained = !scheduler.GetResourceStats().wait_pending;
            io.reset();
            auto& pool = memory::ThreadMemoryPool();
            pool.PurgeIdle();
            const auto footprint = pool.GetFootprint();
            finished.set_value(drained && footprint.mapped_bytes == 0 && footprint.direct_bytes == 0);
        } catch (...) { finished.set_value(false); }
    });
    owner.join();
    return result.get();
}

bool TestDelayCancellationAndReuse() {
    net::io_context io;
    AsyncDelay delay(io);
    bool second_started = false, second_finished = false, early_completion = false;
    auto future = net::co_spawn(io, [&]() -> net::awaitable<void> {
        co_await delay.WaitFor(1h);
        second_started = true;
        co_await delay.WaitFor(1h);
        second_finished = true;
    }, net::use_future);
    net::post(io, [&] { delay.Cancel(); delay.Cancel(); });
    auto& scheduler = TimeoutScheduler::ForIoContext(io);
    Event probe([&] { early_completion = second_finished; delay.Cancel(); });
    (void)scheduler.ScheduleAfter(10ms, probe);
    io.run();
    future.get();
    if (!second_started || !second_finished || early_completion) return false;

    io.restart();
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
    return aborted || parent_observed;
}

bool TestDelayConcurrentWaitAndMaximum() {
    net::io_context io;
    AsyncDelay delay(io);
    auto first = net::co_spawn(io, delay.WaitFor(std::chrono::milliseconds::max()), net::use_future);
    auto second = net::co_spawn(io, delay.WaitFor(1h), net::use_future);
    io.poll();
    bool rejected = false;
    try { second.get(); } catch (const std::logic_error&) { rejected = true; }
    const auto before = timeout_allocation_test::rejected_asio_allocations;
    const auto ordinary_before = rejected_allocations;
    reject_allocations = timeout_allocation_test::reject_asio_allocations = true;
    delay.Cancel();
    timeout_allocation_test::reject_asio_allocations = reject_allocations = false;
    io.run();
    first.get();
    return rejected && timeout_allocation_test::rejected_asio_allocations == before &&
        rejected_allocations == ordinary_before;
}

bool TestDelayCancellationAfterRelease() {
    net::io_context io;
    AsyncDelay delay(io);
    auto waiting = net::co_spawn(io, delay.WaitFor(1h), net::use_future);
    io.poll();
    TimeoutScheduler::ReleaseForIoContext(io);
    delay.Cancel();
    io.restart();
    io.run_for(100ms);
    if (waiting.wait_for(0ms) != std::future_status::ready) return false;
    waiting.get();
    return true;
}

bool TestDomainSchedulerIsolationAndJoin() {
    struct Hooks final : ExecutionDomain::Hooks {
        memory::AllocationDomain allocation;
        std::optional<memory::ScopedAllocationDomain> lease;
        std::exception_ptr failure;
        void Enter() noexcept override { lease.emplace(allocation); }
        void Leave() noexcept override { lease.reset(); }
        void OnFailure(std::exception_ptr error) noexcept override { failure = error; }
    };
    net::io_context io;
    auto coordinator = std::make_shared<GroupCoordinator>(io);
    coordinator->RegisterWorker(0, io, io.get_executor());
    auto first_hooks = std::make_shared<Hooks>();
    auto second_hooks = std::make_shared<Hooks>();
    auto first = ExecutionDomain::Create(io, 0, io.get_executor(), first_hooks, coordinator);
    auto second = ExecutionDomain::Create(io, 0, io.get_executor(), second_hooks, coordinator);
    first_hooks->allocation.SetLeaseGroup(first->LeaseIdentity(), ExecutionDomain::SharesLeaseIdentity);
    second_hooks->allocation.SetLeaseGroup(second->LeaseIdentity(), ExecutionDomain::SharesLeaseIdentity);
    TimeoutScheduler* first_scheduler = nullptr;
    TimeoutScheduler* second_scheduler = nullptr;
    bool first_owner = false, second_owner = false;
    bool first_joined = false, second_joined = false;
    struct WorkerEvent final : TimeoutEvent {
        WorkerEvent() : TimeoutEvent(WorkerLocal{}) {}
        bool fired_on_worker = false;
        void OnTimeout() override { fired_on_worker = !ExecutionDomain::Current(); }
    } worker_event;
    SignalChannel scheduler_joins(io, 2);
    CounterEvent first_pending, second_pending;
    Event first_event([&] {
        first_owner = ExecutionDomain::Current() == first &&
            memory::CurrentAllocationDomain() == &first_hooks->allocation;
        net::co_spawn(first->Executor(), TimeoutScheduler::AsyncReleaseForIoContext(io),
            [&](std::exception_ptr error) {
                first_joined = !error;
                (void)scheduler_joins.try_send(IoErrorCode{});
            });
        throw std::runtime_error("domain timeout callback failed");
    });
    Event second_event([&] {
        second_owner = ExecutionDomain::Current() == second &&
            memory::CurrentAllocationDomain() == &second_hooks->allocation;
        net::co_spawn(second->Executor(), TimeoutScheduler::AsyncReleaseForIoContext(io),
            [&](std::exception_ptr error) {
                second_joined = !error;
                (void)scheduler_joins.try_send(IoErrorCode{});
            });
    });
    first->Execute([&] {
        first_scheduler = &TimeoutScheduler::ForIoContext(io);
        (void)first_scheduler->ScheduleAfter(0ms, first_event);
        (void)first_scheduler->ScheduleAfter(1h, first_pending);
        (void)first_scheduler->ScheduleAfter(2ms, worker_event);
    });
    second->Execute([&] {
        second_scheduler = &TimeoutScheduler::ForIoContext(io);
        (void)second_scheduler->ScheduleAfter(0ms, second_event);
        (void)second_scheduler->ScheduleAfter(1h, second_pending);
    });
    bool passed = false, finalized = false;
    auto finalize = [&](std::shared_ptr<GroupCoordinator> owner) -> net::awaitable<void> {
        co_await scheduler_joins.async_receive(net::use_awaitable);
        co_await scheduler_joins.async_receive(net::use_awaitable);
        passed = first_scheduler && second_scheduler &&
            first_scheduler == second_scheduler && first_owner && second_owner &&
            first_joined && second_joined && !first_pending.Valid() &&
            !second_pending.Valid() && first_hooks->failure && !second_hooks->failure;
        first.reset();
        second.reset();
        owner->CloseAdmission();
        co_await owner->AsyncJoin();
        owner->ReleaseServices();
        co_await owner->Finalize();
    };
    net::co_spawn(io, finalize(coordinator),
        [&](std::exception_ptr error) { finalized = !error; });
    io.run_for(1s);
    return passed && finalized && worker_event.fired_on_worker;
}

bool TestDomainTimeoutHandoff() {
    struct Hooks final : ExecutionDomain::Hooks {
        memory::AllocationDomain allocation;
        std::optional<memory::ScopedAllocationDomain> lease;
        std::exception_ptr failure;
        void Enter() noexcept override { lease.emplace(allocation); }
        void Leave() noexcept override { lease.reset(); }
        void OnFailure(std::exception_ptr error) noexcept override { failure = error; }
    };
    // Let the Worker's native timer expire while domain business is frozen,
    // before the timeout participant removes the remaining active heap slots.
    struct Pause final : ExecutionDomain::NativeResource {
        std::function<void()> on_prepare;
        net::awaitable<void> PrepareHandoff(const ExecutionDomain::HandoffTarget&) override {
            on_prepare();
            net::steady_timer timer(co_await net::this_coro::executor);
            timer.expires_after(40ms);
            co_await timer.async_wait(net::use_awaitable);
        }
        void CommitHandoff(const ExecutionDomain::HandoffTarget&) noexcept override {}
        net::awaitable<void> CancelHandoff(const ExecutionDomain::HandoffTarget&) override { co_return; }
    } pause;
    net::io_context old_io, new_io;
    auto coordinator = std::make_shared<GroupCoordinator>(old_io);
    coordinator->RegisterWorker(0, old_io, old_io.get_executor());
    coordinator->RegisterWorker(1, new_io, new_io.get_executor());
    auto hooks = std::make_shared<Hooks>();
    auto domain = ExecutionDomain::Create(old_io, 0, old_io.get_executor(), hooks, coordinator);
    hooks->allocation.SetLeaseGroup(domain->LeaseIdentity(), ExecutionDomain::SharesLeaseIdentity);
    auto pump = [&] {
        old_io.restart(); old_io.poll();
        new_io.restart(); new_io.poll();
    };
    auto finish = [&](auto& future) {
        const auto limit = std::chrono::steady_clock::now() + 2s;
        while (future.wait_for(0ms) != std::future_status::ready &&
               std::chrono::steady_clock::now() < limit) {
            pump();
            std::this_thread::sleep_for(1ms);
        }
        if (future.wait_for(0ms) != std::future_status::ready)
            throw std::runtime_error("timeout handoff test did not complete");
        return future.get();
    };
    auto wait_until = [&](auto predicate) {
        const auto limit = std::chrono::steady_clock::now() + 2s;
        while (!predicate() && std::chrono::steady_clock::now() < limit) {
            pump();
            std::this_thread::sleep_for(1ms);
        }
        if (!predicate()) throw std::runtime_error("timeout handoff notification missing");
    };
    std::size_t destroyed_calls = 0, rearmed_calls = 0, ready_calls = 0, active_calls = 0;
    bool owner_correct = true;
    auto destroyed = std::make_unique<CounterEvent>();
    destroyed->counter = &destroyed_calls;
    std::size_t cleared_calls = 0;
    CounterEvent cleared;
    cleared.counter = &cleared_calls;
    auto check_owner = [&] {
        owner_correct = owner_correct && ExecutionDomain::Current() == domain &&
            memory::CurrentAllocationDomain() == &hooks->allocation;
    };
    Event rearmed([&] { check_owner(); ++rearmed_calls; });
    Event ready([&] { check_owner(); ++ready_calls; });
    Event active([&] { check_owner(); ++active_calls; });
    std::unique_ptr<AsyncDelay> delay;
    std::future<void> delayed;
    bool delay_on_target = false;
    auto wait_delay = [&]() -> net::awaitable<void> {
        co_await delay->WaitFor(1h);
        check_owner();
        delay_on_target = domain->OwnerId() == 1;
    };
    bool first_preparation = true;
    pause.on_prepare = [&] {
        if (!first_preparation) {
            (void)active.ScheduleAfter(0ms);
            return;
        }
        first_preparation = false;
        // Queue business edits before the native expiry notification, without
        // depending on how quickly the test's control loop obtains its turn.
        domain->Execute([&] {
            destroyed.reset();
            (void)rearmed.ScheduleAfter(2ms);
        });
        (void)destroyed->ScheduleAfter(0ms);
        (void)rearmed.ScheduleAfter(0ms);
        (void)ready.ScheduleAfter(0ms);
        (void)active.ScheduleAfter(90ms);
    };
    auto setup = net::co_spawn(domain->Executor(), [&]() -> net::awaitable<void> {
        auto& scheduler = TimeoutScheduler::ForIoContext(old_io);
        (void)scheduler.ScheduleAfter(1h, *destroyed);
        (void)scheduler.ScheduleAfter(1h, rearmed);
        (void)scheduler.ScheduleAfter(1h, ready);
        (void)scheduler.ScheduleAfter(1h, active);
        (void)scheduler.ScheduleAfter(1h, cleared);
        delay = std::make_unique<AsyncDelay>(old_io);
        delayed = net::co_spawn(domain->Executor(), wait_delay(), net::use_future);
        domain->RegisterResource(pause);
        co_return;
    }, net::use_future);
    finish(setup);
    auto preparation = net::co_spawn(new_io,
        domain->PreparePassiveHandoff({1, &new_io, new_io.get_executor()}), net::use_future);
    auto handoff = finish(preparation);
    bool passed = ready_calls == 0 && rearmed_calls == 0 && active_calls == 0;
    auto validation = net::co_spawn(new_io, handoff->Validate([&] {
        cleared.Cancel(); // Target validation must not touch the old heap.
        passed = passed && !cleared.Valid();
    }), net::use_future);
    finish(validation);
    // The active absolute deadline elapses while prepared. Commit must not
    // restart its duration or wait for a callback on the retired reactor.
    const auto deadline = std::chrono::steady_clock::now() + 70ms;
    while (std::chrono::steady_clock::now() < deadline) {
        pump();
        std::this_thread::sleep_for(1ms);
    }
    auto commit = net::co_spawn(new_io, handoff->Commit(), net::use_future);
    finish(commit);
    handoff.reset();
    const auto delivery_limit = std::chrono::steady_clock::now() + 30ms;
    while ((active_calls == 0 || rearmed_calls == 0) &&
           std::chrono::steady_clock::now() < delivery_limit) {
        // After commit no old reactor polling is needed for expiry delivery.
        new_io.restart(); new_io.poll();
        std::this_thread::sleep_for(1ms);
    }
    passed = passed && domain->OwnerId() == 1 && destroyed_calls == 0 &&
        rearmed_calls == 1 && ready_calls == 1 && active_calls == 1 && owner_correct;
    domain->Execute([&] { delay->Cancel(); });
    finish(delayed);
    passed = passed && delay_on_target;

    // Rollback retains the original absolute deadline and owner. A pending
    // timer must not need a fresh duration, and stop must remove migrated slots.
    auto arm = net::co_spawn(domain->Executor(), [&]() -> net::awaitable<void> {
        (void)active.ScheduleAfter(10ms);
        (void)rearmed.ScheduleAfter(1h);
        co_return;
    }, net::use_future);
    finish(arm);
    preparation = net::co_spawn(old_io,
        domain->PreparePassiveHandoff({0, &old_io, old_io.get_executor()}), net::use_future);
    handoff = finish(preparation);
    passed = passed && active_calls == 1;
    auto rollback = net::co_spawn(old_io, handoff->Cancel(), net::use_future);
    finish(rollback);
    handoff.reset();
    wait_until([&] { return active_calls == 2; });
    passed = passed && domain->OwnerId() == 1 && owner_correct && rearmed.Valid();
    auto shutdown = net::co_spawn(domain->Executor(), [&]() -> net::awaitable<void> {
        domain->UnregisterResource(pause);
        delay.reset();
        co_await TimeoutScheduler::AsyncReleaseForIoContext(new_io);
        passed = passed && !rearmed.Valid() && !active.Valid() &&
            !rearmed.ScheduleAfter(0ms);
    }, net::use_future);
    finish(shutdown);
    passed = passed && !hooks->failure;
    domain.reset();
    auto finalize = net::co_spawn(old_io, [coordinator]() -> net::awaitable<void> {
        coordinator->CloseAdmission();
        co_await coordinator->AsyncJoin();
        coordinator->ReleaseServices();
        co_await coordinator->Finalize();
    }, net::use_future);
    finish(finalize);
    TimeoutScheduler::ReleaseForIoContext(old_io);
    TimeoutScheduler::ReleaseForIoContext(new_io);
    pump();
    return passed && destroyed_calls == 0 && cleared_calls == 0 &&
        rearmed_calls == 1 && active_calls == 2;
}

}  // namespace

TEST(TimeoutScheduler, Contract) {
    const struct { const char* name; bool (*run)(); } cases[] = {
        {"cancel/rearm/destruction without allocation", TestCancellationAndRearm},
        {"reentrant owner destruction and exception isolation", TestReentrantDestructionAndExceptions},
        {"self rearm and I/O fairness", TestSelfRearmAndFairness},
        {"failed wait initiation and recovery", TestWaitInitiationFailureAndRecovery},
        {"heap growth with PMR maintenance reentrancy", TestHeapGrowthAndReentrantMaintenance},
        {"scheduler shard and recycled context ownership", TestShardAndRecycledContextOwnership},
        {"maximum and negative delay", TestMaximumDelay},
        {"pool idle wakeup and OOM recovery", TestPoolMaintenance},
        {"maintenance isolation", TestMaintenanceIsolation},
        {"owner-thread service destruction", TestOwnerThreadServiceDestruction},
        {"delay cancellation and reuse", TestDelayCancellationAndReuse},
        {"delay concurrent wait and maximum", TestDelayConcurrentWaitAndMaximum},
        {"delay cancellation after scheduler release", TestDelayCancellationAfterRelease},
        {"shared Worker scheduler and domain-only release", TestDomainSchedulerIsolationAndJoin},
        {"domain pending expiry, cancellation, rearm and handoff rollback", TestDomainTimeoutHandoff},
    };
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    bool passed = true;
    for (const auto& test : cases) {
        bool result = false;
        try { result = test.run(); }
        catch (const std::exception& error) { std::printf("%s: %s\n", test.name, error.what()); }
        timeout_allocation_test::reject_asio_allocations = reject_allocations = false;
        memory::reject_next_process_allocation = false;
        std::printf("%s: %s\n", test.name, result ? "PASS" : "FAIL");
        passed = passed && result;
    }
    { ASSERT_TRUE(passed); return; }
}

TEST(SessionGroupExecutor, AllocationFailureRollsBackBeforeWorkerStarts) {
    struct Hooks final : ExecutionDomain::Hooks {
        bool entered = false;
        void Enter() noexcept override { entered = true; }
        void Leave() noexcept override { entered = false; }
        void OnFailure(std::exception_ptr) noexcept override { std::terminate(); }
    };
    net::io_context control, worker;
    auto coordinator = std::make_shared<GroupCoordinator>(control);
    coordinator->RegisterWorker(0, worker, worker.get_executor());
    coordinator->Start();
    control.poll();
    bool recovered = false;
    for (std::ptrdiff_t fail_at = 0; fail_at != 64; ++fail_at) {
        auto hooks = std::make_shared<Hooks>();
        const std::weak_ptr<Hooks> released = hooks;
        std::shared_ptr<ExecutionDomain> domain;
        bool failed = false;
        timeout_allocation_test::fail_after = fail_at;
        try {
            domain = ExecutionDomain::Create(
                worker, 0, worker.get_executor(), std::move(hooks), coordinator);
        } catch (const std::bad_alloc&) { failed = true; }
        timeout_allocation_test::fail_after = -1;
        if (failed) {
            EXPECT_TRUE(released.expired())
                << "construction failure retained its host at allocation " << fail_at;
        } else {
            bool entered = false;
            domain->Execute([&] {
                auto owner = released.lock();
                entered = ExecutionDomain::Current() == domain && owner && owner->entered;
            });
            worker.restart();
            worker.poll();
            EXPECT_TRUE(entered) << "recovered domain did not execute under its host lease";
            domain.reset();
            recovered = true;
        }
        // Drain only after checking rollback: a failed candidate must not need
        // a Worker which may never start after construction has thrown.
        worker.restart();
        worker.poll();
        EXPECT_TRUE(released.expired()) << "host survived owner cleanup";
        control.poll();
        if (recovered) break;
    }
    EXPECT_TRUE(recovered) << "allocation sweep never reached a healthy domain";
    bool finalized = false;
    net::co_spawn(control, [coordinator]() -> net::awaitable<void> {
        coordinator->CloseAdmission();
        co_await coordinator->AsyncJoin();
        coordinator->ReleaseServices();
        co_await coordinator->Finalize();
    }, [&](std::exception_ptr error) { finalized = !error; });
    control.restart();
    control.run_for(1s);
    EXPECT_TRUE(finalized) << "construction rollback left coordinator ownership";
}

namespace {
void FailedStartupDoesNotStrandRetirement(bool fail_arm) {
    struct Hooks final : ExecutionDomain::Hooks {
        void Enter() noexcept override {}
        void Leave() noexcept override {}
        void OnFailure(std::exception_ptr) noexcept override { std::terminate(); }
    };
    net::io_context control, worker;
    auto coordinator = std::make_shared<GroupCoordinator>(control);
    coordinator->RegisterWorker(0, worker, worker.get_executor());
    bool failed = false;
    if (fail_arm) coordinator->Start();
    timeout_allocation_test::reject_asio_allocations = true;
    try {
        if (fail_arm) control.poll();
        else coordinator->Start();
    }
    catch (const std::bad_alloc&) { failed = true; }
    timeout_allocation_test::reject_asio_allocations = false;
    EXPECT_TRUE(failed) << "startup allocation fault was not exercised";
    coordinator->Start();
    control.restart();
    control.poll();
    auto hooks = std::make_shared<Hooks>();
    const std::weak_ptr<Hooks> released = hooks;
    auto domain = ExecutionDomain::Create(
        worker, 0, worker.get_executor(), std::move(hooks), coordinator);
    bool finalized = false;
    std::exception_ptr failure;
    net::co_spawn(control, [coordinator]() -> net::awaitable<void> {
        coordinator->CloseAdmission();
        co_await coordinator->AsyncJoin();
        coordinator->ReleaseServices();
        co_await coordinator->Finalize();
    }, [&](std::exception_ptr error) {
        failure = error;
        finalized = true;
    });
    control.restart();
    control.poll();
    EXPECT_FALSE(finalized) << "finalization failed to wait for the live domain";
    domain.reset();
    worker.poll();
    EXPECT_TRUE(released.expired()) << "owner Worker retained the retired host";
    control.restart();
    control.run_for(1s);
    EXPECT_TRUE(finalized)
        << "startup retry did not restore native retirement notifications";
    // Preserve the observation above, then drain a broken implementation so
    // this failure does not leave the fixture's pending Finalize coroutine.
    if (!finalized) {
        net::co_spawn(control, coordinator->AsyncJoin(),
            [&](std::exception_ptr error) { if (error) failure = error; });
        control.restart();
        control.run_for(1s);
    }
    EXPECT_TRUE(finalized) << "manual fixture cleanup did not join finalization";
    EXPECT_FALSE(failure);
}
}  // namespace

TEST(SessionGroupExecutor, FailedStartDoesNotStrandNativeRetirement) {
    FailedStartupDoesNotStrandRetirement(false);
}

TEST(SessionGroupExecutor, FailedNativeArmDoesNotStrandRetirement) {
    FailedStartupDoesNotStrandRetirement(true);
}

namespace {
enum class RearmResolution { Restart, StopRetired, StopLive };

void FailedRearmDoesNotStrandShutdown(RearmResolution resolution) {
    struct Hooks final : ExecutionDomain::Hooks {
        void Enter() noexcept override {}
        void Leave() noexcept override {}
        void OnFailure(std::exception_ptr) noexcept override { std::terminate(); }
    };
    net::io_context control, worker;
    net::posix::stream_descriptor spare(control);
    const int fd = ::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (fd < 0) throw std::runtime_error("cannot create spare native notification");
    try { spare.assign(fd); }
    catch (...) { ::close(fd); throw; }
    auto coordinator = std::make_shared<GroupCoordinator>(control);
    coordinator->RegisterWorker(0, worker, worker.get_executor());
    coordinator->Start();
    control.poll();
    auto hooks = std::make_shared<Hooks>();
    const std::weak_ptr<Hooks> released = hooks;
    auto domain = ExecutionDomain::Create(
        worker, 0, worker.get_executor(), std::move(hooks), coordinator);
    bool spare_completed = false;
    struct ConsumeWaitStorage final : GroupCoordinator::ReservedOperation {
        net::posix::stream_descriptor& spare;
        bool& completed;
        ConsumeWaitStorage(net::posix::stream_descriptor& spare, bool& completed)
            : spare(spare), completed(completed) {}
        void Invoke() noexcept override {
            // Consume the just-completed descriptor wait's recycled block.
            // Rearming the real collector must then cross the fault seam.
            spare.async_wait(net::posix::stream_descriptor::wait_read,
                [flag = &completed](IoErrorCode) { *flag = true; });
            timeout_allocation_test::reject_asio_allocations = true;
        }
    };
    coordinator->PostReserved(
        std::make_unique<ConsumeWaitStorage>(spare, spare_completed));
    bool failed = false;
    try { control.poll(); }
    catch (const std::bad_alloc&) { failed = true; }
    timeout_allocation_test::reject_asio_allocations = false;
    if (!failed) {
        std::fprintf(stderr, "native rearm allocation fault was not exercised\n");
        std::_Exit(2);
    }
    spare.cancel();
    control.restart();
    control.poll();
    if (!spare_completed) {
        std::fprintf(stderr, "spare native wait did not join\n");
        std::_Exit(2);
    }
    if (resolution == RearmResolution::Restart) {
        coordinator->Start();
        control.restart();
        control.poll();
    }
    if (resolution == RearmResolution::StopRetired) {
        domain.reset();
        worker.poll();
    }
    bool finalized = false;
    std::exception_ptr failure;
    net::co_spawn(control, [coordinator]() -> net::awaitable<void> {
        coordinator->CloseAdmission();
        co_await coordinator->AsyncJoin();
        coordinator->ReleaseServices();
        co_await coordinator->Finalize();
    }, [&](std::exception_ptr error) {
        failure = error;
        finalized = true;
    });
    control.restart();
    control.poll();
    if (domain) {
        if (finalized) {
            std::fprintf(stderr, "finalization did not retain the live domain\n");
            std::_Exit(2);
        }
        domain.reset();
        worker.poll();
    }
    control.restart();
    control.run_for(1s);
    if (!finalized || failure || !released.expired()) {
        std::fprintf(stderr, "native rearm failure stranded domain retirement or shutdown\n");
        std::_Exit(1);
    }
    const std::weak_ptr<GroupCoordinator> retired = coordinator;
    coordinator.reset();
    if (!retired.expired()) {
        std::fprintf(stderr, "finalization retained the coordinator\n");
        std::_Exit(2);
    }
}
}  // namespace

TEST(SessionGroupExecutorDeathTest, FailedRearmCanRestart) {
    GTEST_FLAG_SET(death_test_style, "threadsafe");
    EXPECT_EXIT({
        FailedRearmDoesNotStrandShutdown(RearmResolution::Restart);
        std::_Exit(0);
    }, ::testing::ExitedWithCode(0), "");
}

TEST(SessionGroupExecutorDeathTest, FailedRearmCanStopWithRetiredDomains) {
    GTEST_FLAG_SET(death_test_style, "threadsafe");
    EXPECT_EXIT({
        FailedRearmDoesNotStrandShutdown(RearmResolution::StopRetired);
        std::_Exit(0);
    }, ::testing::ExitedWithCode(0), "");
}

TEST(SessionGroupExecutorDeathTest, FailedRearmCanJoinLiveDomains) {
    GTEST_FLAG_SET(death_test_style, "threadsafe");
    EXPECT_EXIT({
        FailedRearmDoesNotStrandShutdown(RearmResolution::StopLive);
        std::_Exit(0);
    }, ::testing::ExitedWithCode(0), "");
}
