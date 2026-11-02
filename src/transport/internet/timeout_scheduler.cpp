#include "acppnode/transport/internet/timeout_scheduler.hpp"
#include "acppnode/common/allocator.hpp"

#include <asio/execution_context.hpp>
#include <asio/steady_timer.hpp>
#include <algorithm>
#include <functional>
#include <stdexcept>

namespace acpp {

struct TimeoutScheduler::Impl : memory::ThreadAllocated {
    explicit Impl(net::io_context& io_context) : timer(io_context) {
        heap.reserve(1024);
    }

    net::steady_timer timer;
    memory::ThreadLocalVector<TimeoutEvent*> heap;
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
    void RequestWakeup() noexcept {
        if (!wait_pending || wakeup_requested) return;
        IoErrorCode ignored;
        timer.cancel(ignored);
        wakeup_requested = true;
    }
    void ArmTimer() {
        const auto deadline = heap.empty() ? maintenance_deadline
            : std::min(heap.front()->deadline_, maintenance_deadline);
        ArmDeadline(deadline);
    }
    // Also called by the allocator during heap reallocation. No heap access.
    void ArmDeadline(std::chrono::steady_clock::time_point deadline) {
        if (dispatching || deadline == std::chrono::steady_clock::time_point::max()) return;
        if (wait_pending) {
            if (deadline < armed_deadline) RequestWakeup();
            return;
        }
        timer.expires_at(deadline);
        timer.async_wait([this](const IoErrorCode& ec) { OnTimer(ec); });
        armed_deadline = deadline;
        wait_pending = true;
        wakeup_requested = false;
    }
    void ReconcileCancellation() noexcept {
        if (heap.empty() && maintenance_deadline == std::chrono::steady_clock::time_point::max())
            RequestWakeup();
    }
    void OnTimer(const IoErrorCode& ec) {
        wait_pending = false;
        wakeup_requested = false;
        if (released) return;
        if (ec && ec != io_error::operation_aborted) throw IoSystemError(ec);

        // Inspect the heap anew after every callback: one event may cancel and
        // destroy another due owner. Never retain a batch of borrowed pointers.
        dispatching = true;
        const auto now = std::chrono::steady_clock::now();
        for (std::size_t count = 0; count != 64 && !released && !heap.empty() &&
             heap.front()->deadline_ <= now; ++count) {
            auto* event = heap.front();
            Remove(*event);
            try { event->OnTimeout(); }
            catch (...) {
                // An owner failure must not unwind the Worker or skip unrelated
                // deadlines. Infrastructure failures still reach runtime owner.
            }
            // The callback may have destroyed event. Do not touch it again.
        }
        if (!released && maintenance && maintenance_deadline <= std::chrono::steady_clock::now()) {
            auto* owner = maintenance;
            maintenance_deadline = std::chrono::steady_clock::time_point::max();
            owner->OnMaintenance();
        }
        dispatching = false;
        if (!released) ArmTimer();
    }
    void Release() noexcept {
        released = true;
        maintenance_deadline = std::chrono::steady_clock::time_point::max();
        maintenance = nullptr;
        RequestWakeup();
        for (auto* event : heap) event->owner_ = nullptr;
        heap.clear();
    }
};

namespace {
thread_local net::io_context* tl_cached_context = nullptr;
thread_local TimeoutScheduler* tl_cached_scheduler = nullptr;
}  // namespace

class TimeoutSchedulerService final : public asio::execution_context::service {
public:
    static asio::execution_context::id id;
    explicit TimeoutSchedulerService(asio::execution_context& ctx)
        : asio::execution_context::service(ctx), scheduler_(static_cast<net::io_context&>(ctx)) {}
    TimeoutScheduler& Scheduler() noexcept { return scheduler_; }
    void ShutdownNow() noexcept { ClearThreadCache(); scheduler_.Release(); }
private:
    void ClearThreadCache() noexcept {
        if (tl_cached_scheduler == &scheduler_) {
            tl_cached_context = nullptr;
            tl_cached_scheduler = nullptr;
        }
    }
    void shutdown() override { ShutdownNow(); }
    TimeoutScheduler scheduler_;
};
asio::execution_context::id TimeoutSchedulerService::id;

TimeoutScheduler::TimeoutScheduler(net::io_context& context) : impl_(std::make_unique<Impl>(context)) {}
TimeoutEvent::~TimeoutEvent() noexcept { Cancel(); }
void TimeoutEvent::Cancel() noexcept { if (owner_) owner_->Cancel(*this); }

TimeoutScheduler& TimeoutScheduler::ForIoContext(net::io_context& context) {
    if (tl_cached_context == &context && tl_cached_scheduler) return *tl_cached_scheduler;
    auto& service = asio::use_service<TimeoutSchedulerService>(context);
    tl_cached_context = &context;
    tl_cached_scheduler = &service.Scheduler();
    return *tl_cached_scheduler;
}
void TimeoutScheduler::ReleaseForIoContext(net::io_context& context) {
    if (tl_cached_context == &context) {
        tl_cached_context = nullptr;
        tl_cached_scheduler = nullptr;
    }
    if (asio::has_service<TimeoutSchedulerService>(context))
        asio::use_service<TimeoutSchedulerService>(context).ShutdownNow();
}
void TimeoutScheduler::Release() noexcept { impl_->Release(); }

bool TimeoutScheduler::ScheduleAfter(std::chrono::milliseconds delay, TimeoutEvent& event) {
    if (impl_->released) return false;
    if (event.owner_ && event.owner_ != this)
        throw std::logic_error("timeout event belongs to another scheduler");
    using Clock = std::chrono::steady_clock;
    const auto now = Clock::now();
    const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::time_point::max() - now);
    delay = std::max(delay, std::chrono::milliseconds::zero());
    const auto deadline = delay >= remaining ? Clock::time_point::max() : now + delay;
    if (event.owner_) {
        event.deadline_ = deadline;
        impl_->Repair(event.index_);
    } else {
        // Publish ownership only after vector growth succeeds.
        impl_->heap.push_back(&event);
        event.index_ = impl_->heap.size() - 1;
        event.deadline_ = deadline;
        event.owner_ = this;
        impl_->SiftUp(event.index_);
    }
    try { impl_->ArmTimer(); }
    catch (...) { Cancel(event); throw; }
    return true;
}
void TimeoutScheduler::Cancel(TimeoutEvent& event) noexcept {
    if (event.owner_ != this) return;
    impl_->Remove(event);
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
    impl_->maintenance_deadline = std::chrono::steady_clock::time_point::max();
    impl_->maintenance = nullptr;
    // No heap inspection: this call may originate from a PMR mutation.
    impl_->RequestWakeup();
}
TimeoutScheduler::ResourceStats TimeoutScheduler::GetResourceStats() const noexcept {
    return {.active_events = impl_->heap.size(),
        .heap_capacity = impl_->heap.capacity(), .wait_pending = impl_->wait_pending};
}

}  // namespace acpp
