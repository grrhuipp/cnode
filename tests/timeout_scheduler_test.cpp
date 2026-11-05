#include "acppnode/transport/internet/timeout_scheduler.hpp"
#include "acppnode/transport/internet/async_delay.hpp"
#include "acppnode/app/session_group_executor.hpp"
#include "../src/app/worker_memory_reclaimer.hpp"

#include <asio/co_spawn.hpp>
#include <asio/bind_cancellation_slot.hpp>
#include <asio/cancellation_signal.hpp>
#include <asio/post.hpp>
#include <asio/use_future.hpp>

#include <chrono>
#include <cstdio>
#include <deque>
#include <future>
#include <memory>
#include <optional>
#include <stdexcept>
#include <thread>
#include <utility>
#include <vector>

namespace {
using namespace acpp;
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
    io.run();
    if (owner || cancelled_calls || survivor_calls != 1) return false;

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
    (void)scheduler.ScheduleAfter(-1ms, immediate);
    io.run_for(10ms);
    scheduler.Cancel(maximum);
    io.restart();
    io.run();
    return far_calls == 0 && immediate_calls == 1;
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
            first_scheduler != second_scheduler && first_owner && second_owner &&
            first_joined && second_joined && !first_pending.Valid() &&
            !second_pending.Valid() && !first_hooks->failure && !second_hooks->failure;
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
    return passed && finalized;
}

}  // namespace

int main() {
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
        {"domain scheduler isolation and native timer join", TestDomainSchedulerIsolationAndJoin},
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
    return passed ? 0 : 1;
}
