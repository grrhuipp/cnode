#include "transport/timeout_scheduler.hpp"
#include "common/allocator.hpp"

#include <asio/as_tuple.hpp>
#include <asio/execution_context.hpp>
#include <asio/steady_timer.hpp>
#include <asio/this_coro.hpp>
#include <asio/use_awaitable.hpp>
#include <algorithm>
#include <functional>
#include <optional>
#include <stdexcept>
#include <vector>


struct transport::TimeoutScheduler::Impl {
    explicit Impl(net::io_context& context) : context(context), timer(context) {
        heap.reserve(1024);
    }

    net::io_context& context;
    net::steady_timer timer;
    std::vector<transport::TimeoutEvent*> heap;
    uint64_t next_sequence = 0;
    std::optional<common::SignalChannel> join;
    bool wait_pending = false;
    bool wakeup_requested = false;
    bool released = false;
    bool dispatching = false;
    std::chrono::steady_clock::time_point armed_deadline{};

    static bool Before(const transport::TimeoutEvent* lhs, const transport::TimeoutEvent* rhs) noexcept {
        if (lhs->deadline_ != rhs->deadline_) return lhs->deadline_ < rhs->deadline_;
        if (lhs->sequence_ != rhs->sequence_) return lhs->sequence_ < rhs->sequence_;
        return std::less<const transport::TimeoutEvent*>{}(lhs, rhs);
    }
    void Place(std::size_t index, transport::TimeoutEvent* event) noexcept {
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
    void Remove(transport::TimeoutEvent& event) noexcept {
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
        const auto needed = heap.size() + count;
        if (needed > heap.capacity()) heap.reserve(std::max(needed, heap.capacity() * 2));
    }
    void Insert(transport::TimeoutScheduler& scheduler, transport::TimeoutEvent& event) noexcept {
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
        // A live event at max() still needs a cancellable native wait.
        if (released || dispatching || heap.empty()) return;
        const auto deadline = heap.front()->deadline_;
        if (wait_pending) {
            if (deadline < armed_deadline) RequestWakeup();
            return;
        }
        timer.expires_at(deadline);
        common::CheckTestAllocationFault();
        timer.async_wait([this](const IoErrorCode& ec) { OnTimer(ec); });
        armed_deadline = deadline;
        wait_pending = true;
        wakeup_requested = false;
    }
    void ReconcileCancellation() noexcept {
        if (heap.empty()) RequestWakeup();
    }
    void OnTimer(const IoErrorCode& ec);
    void Release() noexcept;
};

namespace transport {

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
            Remove(*event);
            event->OnTimeout();
        }
    } catch (...) {
        dispatching = false;
        if (!released) ArmTimer();
        throw;
    }
    dispatching = false;
    if (!released) ArmTimer();
}

void TimeoutScheduler::Impl::Release() noexcept {
    released = true;
    RequestWakeup();
    while (!heap.empty()) heap.back()->Cancel();
    std::vector<TimeoutEvent*>{}.swap(heap);
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
    : context_(&context) {}
TimeoutEvent::~TimeoutEvent() noexcept { Cancel(); }
void TimeoutEvent::Cancel() noexcept {
    if (owner_) owner_->Cancel(*this);
}
bool TimeoutEvent::ScheduleAfter(std::chrono::milliseconds delay) {
    if (!context_) throw std::logic_error("timeout event has no scheduling context");
    return TimeoutScheduler::ForIoContext(*context_).ScheduleAfter(delay, *this);
}

TimeoutScheduler& TimeoutScheduler::ForIoContext(net::io_context& context) {
    if (tl_cached_context == &context && tl_cached_scheduler) return *tl_cached_scheduler;
    auto& service = asio::use_service<TimeoutSchedulerService>(context);
    tl_cached_context = &context;
    tl_cached_scheduler = &service.Scheduler();
    return *tl_cached_scheduler;
}
void TimeoutScheduler::ReleaseForIoContext(net::io_context& context) {
    if (asio::has_service<TimeoutSchedulerService>(context))
        asio::use_service<TimeoutSchedulerService>(context).ShutdownNow();
}
net::awaitable<void> TimeoutScheduler::AsyncReleaseForIoContext(net::io_context& context) {
    co_await net::this_coro::reset_cancellation_state(net::disable_cancellation());
    if (!asio::has_service<TimeoutSchedulerService>(context)) co_return;
    auto& service = asio::use_service<TimeoutSchedulerService>(context);
    auto& impl = *service.Scheduler().impl_;
    service.ShutdownNow();
    if (!impl.wait_pending) co_return;
    if (impl.join) throw std::logic_error("concurrent timeout scheduler join");
    impl.join.emplace(co_await net::this_coro::executor, 1);
    struct JoinReset {
        std::optional<common::SignalChannel>& channel;
        ~JoinReset() { channel.reset(); }
    } reset{impl.join};
    auto [ec] = co_await impl.join->async_receive(
        net::as_tuple(net::use_awaitable));
    if (ec) throw IoSystemError(ec);
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
        event.sequence_ = ++impl_->next_sequence;
        impl_->Repair(event.index_);
    } else {
        impl_->Reserve(1);
        event.context_ = &impl_->context;
        event.deadline_ = deadline;
        event.sequence_ = ++impl_->next_sequence;
        impl_->Insert(*this, event);
    }
    try { impl_->ArmTimer(); }
    catch (...) { event.Cancel(); throw; }
    return true;
}
void TimeoutScheduler::Cancel(TimeoutEvent& event) noexcept {
    if (event.owner_ != this) return;
    impl_->Remove(event);
    impl_->ReconcileCancellation();
}
TimeoutScheduler::ResourceStats TimeoutScheduler::GetResourceStats() const noexcept {
    return {.active_events = impl_->heap.size(), .heap_capacity = impl_->heap.capacity(),
        .wait_pending = impl_->wait_pending};
}

}  // namespace transport
