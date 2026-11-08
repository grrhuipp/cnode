#include "transport/internet/timeout_scheduler.hpp"
#include "common/allocator.hpp"
#include "app/session_group_executor.hpp"

#include <asio/as_tuple.hpp>
#include <asio/bind_allocator.hpp>
#include <asio/co_spawn.hpp>
#include <asio/execution_context.hpp>
#include <asio/steady_timer.hpp>
#include <asio/this_coro.hpp>
#include <asio/use_awaitable.hpp>
#include <algorithm>
#include <atomic>
#include <functional>
#include <optional>
#include <stdexcept>
#include <vector>


struct TimeoutScheduler::Impl {
    explicit Impl(net::io_context& context) : context(context), timer(context) {
        heap.reserve(1024);
    }

    net::io_context& context;
    net::steady_timer timer;
    // Shared Worker bookkeeping must never allocate from the calling domain.
    std::vector<TimeoutEvent*, memory::ProcessAllocator<TimeoutEvent*>> heap;
    // A reservation may be retired from the opposite native owner on commit or
    // rollback. Heap storage itself is accessed only on its owning Worker.
    std::atomic_size_t reserved{0};
    uint64_t next_sequence = 0;
    std::optional<SignalChannel> join;
    bool wait_pending = false;
    bool wakeup_requested = false;
    bool released = false;
    bool dispatching = false;
    std::chrono::steady_clock::time_point armed_deadline{};
    std::chrono::steady_clock::time_point maintenance_deadline =
        std::chrono::steady_clock::time_point::max();
    TimeoutMaintenance* maintenance = nullptr;

    static bool Before(const TimeoutEvent* lhs, const TimeoutEvent* rhs) noexcept {
        if (lhs->deadline_ != rhs->deadline_) return lhs->deadline_ < rhs->deadline_;
        if (lhs->sequence_ != rhs->sequence_) return lhs->sequence_ < rhs->sequence_;
        return std::less<const TimeoutEvent*>{}(lhs, rhs);
    }
    void Place(std::size_t index, TimeoutEvent* event) noexcept {
        heap[index] = event;
        event->index_ = index;
    }
    void SiftUp(std::size_t index) noexcept {
        auto* event = heap[index];
        while (index != 0) {
            const auto parent = (index - 1) / 2;
            if (!Before(event, heap[parent])) break;
            Place(index, heap[parent]);
            index = parent;
        }
        Place(index, event);
    }
    void SiftDown(std::size_t index) noexcept {
        auto* event = heap[index];
        while (index < heap.size() / 2) {
            auto child = index * 2 + 1;
            if (child + 1 < heap.size() && Before(heap[child + 1], heap[child])) ++child;
            if (!Before(heap[child], event)) break;
            Place(index, heap[child]);
            index = child;
        }
        Place(index, event);
    }
    void Repair(std::size_t index) noexcept {
        if (index != 0 && Before(heap[index], heap[(index - 1) / 2])) SiftUp(index);
        else SiftDown(index);
    }
    void Remove(TimeoutEvent& event) noexcept {
        const auto index = event.index_;
        auto* last = heap.back();
        heap.pop_back();
        event.owner_ = nullptr;
        if (index != heap.size()) {
            Place(index, last);
            Repair(index);
        }
    }
    void Reserve(std::size_t count) {
        const auto needed = heap.size() + reserved.load(std::memory_order_relaxed) + count;
        if (needed > heap.capacity()) heap.reserve(std::max(needed, heap.capacity() * 2));
    }
    void Insert(TimeoutScheduler& scheduler, TimeoutEvent& event) noexcept {
        // Schedule and handoff Prepare reserve before publishing ownership.
        heap.push_back(&event);
        event.owner_ = &scheduler;
        event.index_ = heap.size() - 1;
        SiftUp(event.index_);
    }
    void RequestWakeup() noexcept {
        if (!wait_pending || wakeup_requested) return;
        timer.cancel();
        wakeup_requested = true;
    }
    void ArmTimer() {
        const auto deadline = heap.empty() ? maintenance_deadline
            : std::min(heap.front()->deadline_, maintenance_deadline);
        ArmDeadline(deadline);
    }
    void ArmDeadline(std::chrono::steady_clock::time_point deadline) {
        // A live event at max() still needs a cancellable native wait. Only an
        // empty heap uses max() to mean that no deadline is armed.
        if (released || dispatching ||
            (deadline == std::chrono::steady_clock::time_point::max() && heap.empty())) return;
        if (wait_pending) {
            if (deadline < armed_deadline) RequestWakeup();
            return;
        }
        timer.expires_at(deadline);
        timer.async_wait(net::bind_allocator(memory::ProcessAllocator<std::byte>{},
            [this](const IoErrorCode& ec) { OnTimer(ec); }));
        armed_deadline = deadline;
        wait_pending = true;
        wakeup_requested = false;
    }
    void ReconcileCancellation() noexcept {
        if (heap.empty() && maintenance_deadline == std::chrono::steady_clock::time_point::max())
            RequestWakeup();
    }
    void OnTimer(const IoErrorCode& ec);
    void Release() noexcept;
};

// Only intrusive event membership and one coalesced business notification live
// in a domain. In particular this service owns no timer, heap, or PMR arena.
class DomainTimeouts final : public asio::execution_context::service,
                             public ExecutionDomain::NativeResource {
public:
    static asio::execution_context::id id;
    explicit DomainTimeouts(asio::execution_context& context)
        : DomainTimeouts(context, ExecutionDomain::Current()) {}
    DomainTimeouts(asio::execution_context& context, std::shared_ptr<ExecutionDomain> domain)
        : asio::execution_context::service(context), domain_(domain) {
        if (!domain || &domain->Services() != &context)
            throw std::logic_error("timeout domain service requires its owner lease");
        domain->RegisterResource(*this);
    }
    static DomainTimeouts& ForDomain(const std::shared_ptr<ExecutionDomain>& domain) {
        auto caller = ExecutionDomain::Current();
        if (!caller || !caller->SharesGroup(*domain))
            throw std::logic_error("timeout scheduling requires its domain lease");
        auto& services = domain->Services();
        if (!asio::has_service<DomainTimeouts>(services))
            return asio::make_service<DomainTimeouts>(services, domain);
        return asio::use_service<DomainTimeouts>(services);
    }
    void Attach(TimeoutEvent& event) noexcept {
        event.domain_owner_ = this;
        event.previous_ = nullptr;
        event.next_ = first_;
        if (first_) first_->previous_ = &event;
        first_ = &event;
    }
    void Detach(TimeoutEvent& event) noexcept {
        if (event.ready_) {
            if (event.ready_previous_) event.ready_previous_->ready_next_ = event.ready_next_;
            else ready_first_ = event.ready_next_;
            if (event.ready_next_) event.ready_next_->ready_previous_ = event.ready_previous_;
            else ready_last_ = event.ready_previous_;
            event.ready_previous_ = event.ready_next_ = nullptr;
            event.ready_ = false;
        }
        if (event.previous_) event.previous_->next_ = event.next_;
        else first_ = event.next_;
        if (event.next_) event.next_->previous_ = event.previous_;
        event.previous_ = event.next_ = nullptr;
        event.domain_owner_ = nullptr;
    }
    void Queue(TimeoutEvent& event) {
        // Enqueue first: failure leaves the event in the live heap, rather than
        // leaving an expiry with no notification capable of consuming it.
        Notify();
        event.owner_->impl_->Remove(event);
        event.ready_ = true;
        event.ready_previous_ = ready_last_;
        event.ready_next_ = nullptr;
        if (ready_last_) ready_last_->ready_next_ = &event;
        else ready_first_ = &event;
        ready_last_ = &event;
    }
    void Release() noexcept {
        released_ = true;
        while (first_) first_->Cancel();
    }
    [[nodiscard]] bool Released() const noexcept { return released_; }
    void RequireArmable() const {
        if (prepared_) throw std::logic_error("arming timeout during handoff validation");
    }

    net::awaitable<void> PrepareHandoff(const ExecutionDomain::HandoffTarget& target) override {
        co_await net::this_coro::reset_cancellation_state(net::disable_cancellation());
        if (prepared_) throw std::logic_error("timeout handoff already prepared");
        if (released_) co_return;
        auto domain = domain_.lock();
        old_ = &TimeoutScheduler::ForWorker(domain->Reactor());
        std::size_t count = 0;
        for (auto* event = first_; event; event = event->next_) if (event->owner_) ++count;
        // This preallocated business notification resumes on whichever route is
        // committed. Thus Commit only links reserved heap slots: even starting
        // the native wait (which can allocate) stays outside noexcept Commit.
        Notify();
        co_await net::co_spawn(target.executor,
            ReserveTarget(*target.reactor, count), net::use_awaitable);
        old_reserved_ = 0;
        for (auto* event = first_; event; event = event->next_) {
            if (!event->owner_) continue; // Already queued, never resurrect it.
            old_->impl_->Remove(*event);
            ++old_reserved_;
        }
        old_->impl_->reserved.fetch_add(old_reserved_, std::memory_order_relaxed);
        old_->impl_->ReconcileCancellation();
        prepared_ = true;
    }
    void CommitHandoff(const ExecutionDomain::HandoffTarget&) noexcept override {
        if (!prepared_) return;
        Restore(*target_);
        DropReservations();
    }
    net::awaitable<void> CancelHandoff(const ExecutionDomain::HandoffTarget&) override {
        if (prepared_) Restore(*old_);
        if (prepared_ || target_reserved_ != 0 || old_reserved_ != 0 || old_ || target_)
            DropReservations();
        co_return;
    }
private:
    net::awaitable<void> ReserveTarget(net::io_context& context, std::size_t count) {
        auto& scheduler = TimeoutScheduler::ForWorker(context);
        if (scheduler.impl_->released) throw std::logic_error("target timeout scheduler released");
        scheduler.impl_->Reserve(count);
        scheduler.impl_->reserved.fetch_add(count, std::memory_order_relaxed);
        target_ = &scheduler;
        target_reserved_ = count;
        co_return;
    }
    void Restore(TimeoutScheduler& scheduler) noexcept {
        for (auto* event = first_; event; event = event->next_)
            if (!event->ready_) scheduler.impl_->Insert(scheduler, *event);
    }
    void DropReservations() noexcept {
        if (old_) old_->impl_->reserved.fetch_sub(old_reserved_, std::memory_order_relaxed);
        if (target_) target_->impl_->reserved.fetch_sub(target_reserved_, std::memory_order_relaxed);
        old_ = target_ = nullptr;
        old_reserved_ = target_reserved_ = 0;
        prepared_ = false;
    }
    void Notify() {
        if (notification_pending_) return;
        auto domain = domain_.lock();
        if (!domain) throw std::logic_error("timeout owner retired before notification");
        domain->Execute([this, keep_alive = domain] { Drain(); });
        notification_pending_ = true;
    }
    void Drain() {
        notification_pending_ = false;
        if (released_) return;
        auto domain = domain_.lock();
        auto& scheduler = TimeoutScheduler::ForWorker(domain->Reactor());
        try { scheduler.impl_->ArmTimer(); }
        catch (...) {
            // Fail only this domain. Its owners must not remain armed forever
            // after the failure is delivered to their lifecycle hook.
            Release();
            scheduler.impl_->ArmTimer();
            throw;
        }
        // Never capture an event pointer in an asynchronous callback. Cancellation
        // or destruction removes it from this list before the queued drain runs.
        for (std::size_t count = 0; count != 64 && ready_first_; ++count) {
            auto* event = ready_first_;
            Detach(*event);
            try { event->OnTimeout(); }
            catch (...) {
                // The event may already have destroyed itself. Retire this
                // domain's remaining waits before its executor reports failure
                // to the owning session; unrelated domains keep their timers.
                Release();
                throw;
            }
        }
        if (ready_first_) Notify();
    }
    void shutdown() override { Release(); }
    std::weak_ptr<ExecutionDomain> domain_;
    TimeoutEvent* first_ = nullptr;
    TimeoutEvent* ready_first_ = nullptr;
    TimeoutEvent* ready_last_ = nullptr;
    TimeoutScheduler* old_ = nullptr;
    TimeoutScheduler* target_ = nullptr;
    std::size_t old_reserved_ = 0;
    std::size_t target_reserved_ = 0;
    bool notification_pending_ = false;
    bool prepared_ = false;
    bool released_ = false;
};
asio::execution_context::id DomainTimeouts::id;

void TimeoutScheduler::Impl::OnTimer(const IoErrorCode& ec) {
    wait_pending = false;
    wakeup_requested = false;
    if (released) {
        if (join) (void)join->try_send(IoErrorCode{});
        return;
    }
    if (ec && ec != io_error::operation_aborted) throw IoSystemError(ec);
    dispatching = true;
    try {
        const auto now = std::chrono::steady_clock::now();
        for (std::size_t count = 0; count != 64 && !released && !heap.empty() &&
             heap.front()->deadline_ <= now; ++count) {
            auto* event = heap.front();
            if (event->domain_owner_) event->domain_owner_->Queue(*event);
            else {
                Remove(*event);
                event->OnTimeout();
            }
        }
        if (!released && maintenance && maintenance_deadline <= std::chrono::steady_clock::now()) {
            auto* owner = maintenance;
            maintenance_deadline = std::chrono::steady_clock::time_point::max();
            owner->OnMaintenance();
        }
    } catch (...) {
        dispatching = false;
        // Unscoped Worker callbacks have no session failure hook. Preserve
        // unrelated waits, then propagate to the runtime's error boundary.
        if (!released) ArmTimer();
        throw;
    }
    dispatching = false;
    if (!released) ArmTimer();
}
void TimeoutScheduler::Impl::Release() noexcept {
    released = true;
    maintenance_deadline = std::chrono::steady_clock::time_point::max();
    maintenance = nullptr;
    RequestWakeup();
    while (!heap.empty()) heap.back()->Cancel();
    decltype(heap){}.swap(heap);
}

namespace {
thread_local net::io_context* tl_cached_context = nullptr;
thread_local TimeoutScheduler* tl_cached_scheduler = nullptr;
}  // namespace

class TimeoutSchedulerService final : public asio::execution_context::service {
public:
    static asio::execution_context::id id;
    explicit TimeoutSchedulerService(asio::execution_context& context)
        : asio::execution_context::service(context), scheduler_(static_cast<net::io_context&>(context)) {}
    TimeoutScheduler& Scheduler() noexcept { return scheduler_; }
    void ShutdownNow() noexcept {
        if (tl_cached_scheduler == &scheduler_) {
            tl_cached_context = nullptr;
            tl_cached_scheduler = nullptr;
        }
        scheduler_.Release();
    }
private:
    void shutdown() override { ShutdownNow(); }
    TimeoutScheduler scheduler_;
};
asio::execution_context::id TimeoutSchedulerService::id;

TimeoutScheduler::TimeoutScheduler(net::io_context& context) : impl_(std::make_unique<Impl>(context)) {}
TimeoutEvent::TimeoutEvent(net::io_context& context) noexcept
    : domain_(ExecutionDomain::Current()), context_(&context), domain_bound_(!domain_.expired()) {}
TimeoutEvent::~TimeoutEvent() noexcept { Cancel(); }
void TimeoutEvent::Cancel() noexcept {
    if (owner_) owner_->Cancel(*this);
    else if (domain_owner_) domain_owner_->Detach(*this);
}
bool TimeoutEvent::ScheduleAfter(std::chrono::milliseconds delay) {
    if (auto domain = domain_.lock()) {
        DomainTimeouts::ForDomain(domain).RequireArmable();
        return TimeoutScheduler::ForWorker(domain->Reactor()).ScheduleAfter(delay, *this);
    }
    if (domain_bound_) return false;
    if (!context_) throw std::logic_error("timeout event has no scheduling context");
    return (worker_local_ ? TimeoutScheduler::ForWorker(*context_)
                          : TimeoutScheduler::ForIoContext(*context_)).ScheduleAfter(delay, *this);
}
bool TimeoutEvent::ScheduleAfter(std::chrono::milliseconds delay, net::io_context& context) {
    if (!context_) context_ = &context;
    return ScheduleAfter(delay);
}

TimeoutScheduler& TimeoutScheduler::ForWorker(net::io_context& context) {
    if (tl_cached_context == &context && tl_cached_scheduler) return *tl_cached_scheduler;
    auto& service = asio::use_service<TimeoutSchedulerService>(context);
    tl_cached_context = &context;
    tl_cached_scheduler = &service.Scheduler();
    return *tl_cached_scheduler;
}
TimeoutScheduler& TimeoutScheduler::ForIoContext(net::io_context& context) {
    if (auto domain = ExecutionDomain::Current()) return ForWorker(domain->Reactor());
    return ForWorker(context);
}
void TimeoutScheduler::ReleaseForIoContext(net::io_context& context) {
    if (auto domain = ExecutionDomain::Current()) {
        if (asio::has_service<DomainTimeouts>(domain->Services()))
            asio::use_service<DomainTimeouts>(domain->Services()).Release();
        return;
    }
    if (asio::has_service<TimeoutSchedulerService>(context))
        asio::use_service<TimeoutSchedulerService>(context).ShutdownNow();
}
net::awaitable<void> TimeoutScheduler::AsyncReleaseForIoContext(net::io_context& context) {
    co_await net::this_coro::reset_cancellation_state(net::disable_cancellation());
    if (auto domain = ExecutionDomain::Current()) {
        ReleaseForIoContext(context);
        co_return;
    }
    if (!asio::has_service<TimeoutSchedulerService>(context)) co_return;
    auto& service = asio::use_service<TimeoutSchedulerService>(context);
    auto& impl = *service.Scheduler().impl_;
    service.ShutdownNow();
    if (!impl.wait_pending) co_return;
    if (impl.join) throw std::logic_error("concurrent timeout scheduler join");
    impl.join.emplace(co_await net::this_coro::executor, 1);
    struct JoinReset {
        std::optional<SignalChannel>& channel;
        ~JoinReset() { channel.reset(); }
    } reset{impl.join};
    auto [ec] = co_await impl.join->async_receive(
        net::bind_allocator(memory::ProcessAllocator<std::byte>{}, net::as_tuple(net::use_awaitable)));
    if (ec) throw IoSystemError(ec);
}
void TimeoutScheduler::Release() noexcept { impl_->Release(); }

bool TimeoutScheduler::ScheduleAfter(std::chrono::milliseconds delay, TimeoutEvent& event) {
    auto domain = event.domain_.lock();
    if (!domain && event.domain_bound_) return false;
    if (!domain && !event.worker_local_) domain = ExecutionDomain::Current();
    DomainTimeouts* domain_owner = nullptr;
    if (domain) {
        domain_owner = &DomainTimeouts::ForDomain(domain);
        domain_owner->RequireArmable();
        if (domain_owner->Released()) return false;
        auto& current = ForWorker(domain->Reactor());
        if (&current != this) return current.ScheduleAfter(delay, event);
    }
    if (impl_->released) return false;
    if (event.owner_ && event.owner_ != this)
        throw std::logic_error("timeout event belongs to another scheduler");
    // Expediting an already-queued expiry needs neither another heap slot nor
    // another completion; in particular AsyncDelay cancellation stays bounded.
    if (event.ready_ && delay <= std::chrono::milliseconds::zero()) return true;
    using Clock = std::chrono::steady_clock;
    const auto now = Clock::now();
    const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::time_point::max() - now);
    delay = std::max(delay, std::chrono::milliseconds::zero());
    const auto deadline = delay >= remaining ? Clock::time_point::max() : now + delay;
    if (event.owner_) {
        if (domain_owner && !event.domain_owner_) {
            event.domain_ = domain;
            event.domain_bound_ = true;
            domain_owner->Attach(event);
        }
        event.deadline_ = deadline;
        event.sequence_ = ++impl_->next_sequence;
        impl_->Repair(event.index_);
    } else {
        // Queued expiry is withdrawn before rearming; no queued closure borrows
        // this event, so neither destruction nor reschedule needs a tombstone.
        event.Cancel();
        impl_->Reserve(1);
        event.context_ = &impl_->context;
        event.domain_ = domain;
        event.domain_bound_ = bool(domain);
        event.deadline_ = deadline;
        event.sequence_ = ++impl_->next_sequence;
        if (domain_owner) domain_owner->Attach(event);
        impl_->Insert(*this, event);
    }
    try { impl_->ArmTimer(); }
    catch (...) { event.Cancel(); throw; }
    return true;
}
void TimeoutScheduler::Cancel(TimeoutEvent& event) noexcept {
    if (event.owner_ != this) return;
    impl_->Remove(event);
    if (event.domain_owner_) event.domain_owner_->Detach(event);
    impl_->ReconcileCancellation();
}
bool TimeoutScheduler::SetMaintenanceDeadline(
    TimeoutMaintenance& owner, std::chrono::steady_clock::time_point deadline) {
    if (impl_->released) return false;
    if (impl_->maintenance && impl_->maintenance != &owner)
        throw std::logic_error("timeout maintenance owner conflict");
    impl_->maintenance = &owner;
    impl_->maintenance_deadline = deadline;
    impl_->ArmDeadline(deadline);
    return true;
}
void TimeoutScheduler::CancelMaintenance(TimeoutMaintenance& owner) noexcept {
    if (impl_->maintenance != &owner) return;
    const auto old_deadline = std::exchange(impl_->maintenance_deadline,
        std::chrono::steady_clock::time_point::max());
    impl_->maintenance = nullptr;
    if (impl_->armed_deadline >= old_deadline) impl_->RequestWakeup();
}
TimeoutScheduler::ResourceStats TimeoutScheduler::GetResourceStats() const noexcept {
    return {.active_events = impl_->heap.size(), .heap_capacity = impl_->heap.capacity(),
        .wait_pending = impl_->wait_pending};
}

