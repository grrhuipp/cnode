#include "acppnode/transport/internet/timeout_scheduler.hpp"
#include "acppnode/common/allocator.hpp"

#include <algorithm>
#include <stdexcept>
#include <asio/execution_context.hpp>
#include <asio/steady_timer.hpp>


namespace acpp {

struct TimeoutScheduler::Impl {
    explicit Impl(net::io_context& io_context)
        : timer(io_context) {
        events.reserve(kInitialEventReserve);
        deadline_heap.reserve(kInitialEventReserve);
        ready_event_ids.reserve(kMaxReadyBatch);
    }

    static constexpr size_t kInitialEventReserve = 1024;
    static constexpr size_t kMaxReadyBatch = 64;
    static constexpr size_t kHeapCompactStaleFloor = 1024;

    struct Event {
        std::chrono::steady_clock::time_point deadline;
        Callback cb;
    };

    struct HeapEntry {
        std::chrono::steady_clock::time_point deadline;
        uint64_t id = 0;
    };

    struct HeapCompare {
        bool operator()(const HeapEntry& lhs, const HeapEntry& rhs) const noexcept {
            if (lhs.deadline == rhs.deadline) {
                return lhs.id > rhs.id;
            }
            return lhs.deadline > rhs.deadline;
        }
    };

    net::steady_timer timer;
    using TimeoutEventMap = memory::ThreadLocalUnorderedMap<uint64_t, Event>;

    TimeoutEventMap events;
    memory::ThreadLocalVector<HeapEntry> deadline_heap;
    memory::ThreadLocalVector<uint64_t> ready_event_ids;
    uint64_t next_id = 1;
    bool wait_pending = false;
    bool wakeup_requested = false;
    bool released = false;
    bool dispatching_ready_batch = false;
    std::chrono::steady_clock::time_point armed_deadline{};
    std::chrono::steady_clock::time_point maintenance_deadline =
        std::chrono::steady_clock::time_point::max();
    void* maintenance_owner = nullptr;
    void (*maintenance_callback)(void*) noexcept = nullptr;

    void PushHeap(HeapEntry entry) {
        deadline_heap.push_back(entry);
        std::push_heap(deadline_heap.begin(), deadline_heap.end(), HeapCompare{});
    }

    HeapEntry PopHeap() {
        std::pop_heap(deadline_heap.begin(), deadline_heap.end(), HeapCompare{});
        auto entry = deadline_heap.back();
        deadline_heap.pop_back();
        return entry;
    }

    void PruneHeapTop() {
        while (!deadline_heap.empty()) {
            const auto& top = deadline_heap.front();
            auto it = events.find(top.id);
            if (it != events.end() && it->second.deadline == top.deadline) {
                return;
            }
            (void)PopHeap();
        }
    }

    void MaybeCompactHeap() noexcept {
        if (released || dispatching_ready_batch ||
            deadline_heap.size() <= events.size()) {
            return;
        }

        const size_t stale = deadline_heap.size() - events.size();
        if (stale < kHeapCompactStaleFloor ||
            stale < deadline_heap.size() / 2) {
            return;
        }

        // The index contains trivial values, so cancelled entries can be
        // removed in place. Cancellation and owner destruction never need a
        // replacement allocation, even when the stale tail is large.
        std::erase_if(deadline_heap, [this](const HeapEntry& entry) {
            const auto it = events.find(entry.id);
            return it == events.end() || it->second.deadline != entry.deadline;
        });
        std::make_heap(deadline_heap.begin(), deadline_heap.end(), HeapCompare{});
    }

    void RequestWakeup() noexcept {
        if (!wait_pending || wakeup_requested) {
            return;
        }
        IoErrorCode ec;
        timer.cancel(ec);
        wakeup_requested = true;
    }

    void ArmTimer() {
        PruneHeapTop();
        const auto next_deadline = deadline_heap.empty() ? maintenance_deadline
            : std::min(deadline_heap.front().deadline, maintenance_deadline);
        if (next_deadline == std::chrono::steady_clock::time_point::max()) return;

        if (wait_pending) {
            // Preserve the existing operation until its completion is
            // delivered. An earlier event only wakes it; scheduling a second
            // wait here could cancel the old one and then fail to allocate.
            if (next_deadline < armed_deadline) {
                RequestWakeup();
            }
            return;
        }

        timer.expires_at(next_deadline);
        timer.async_wait([this](const IoErrorCode& ec) {
            OnTimer(ec);
        });
        // async_wait never invokes inline. Publish ownership only after its
        // initiation succeeds; an exception must leave no fictitious wait.
        armed_deadline = next_deadline;
        wait_pending = true;
        wakeup_requested = false;
    }

    void ReconcileTimerAfterCancellation() noexcept {
        PruneHeapTop();
        // A later remaining deadline can use the already-armed earlier wake.
        // With no events, wake now so io_context::run can finish promptly.
        if (deadline_heap.empty() &&
            maintenance_deadline == std::chrono::steady_clock::time_point::max()) {
            RequestWakeup();
        }
    }

    void OnTimer(const IoErrorCode& ec) {
        wait_pending = false;
        wakeup_requested = false;
        if (released) return;
        if (ec && ec != io_error::operation_aborted) {
            throw IoSystemError(ec);
        }

        auto& ready = ready_event_ids;
        ready.clear();

        const auto now = std::chrono::steady_clock::now();
        while (ready.size() < kMaxReadyBatch) {
            PruneHeapTop();
            if (deadline_heap.empty() || deadline_heap.front().deadline > now) {
                break;
            }

            const auto entry = PopHeap();
            auto it = events.find(entry.id);
            if (it == events.end() || it->second.deadline != entry.deadline) {
                continue;
            }
            ready.push_back(entry.id);
        }

        // Keep due callbacks in events until the instant they execute. A prior
        // callback in this same ready batch may cancel and destroy a later
        // callback owner; Cancel must still be able to erase that event.
        dispatching_ready_batch = true;
        for (size_t i = 0; i < ready.size(); ++i) {
            const uint64_t id = ready[i];
            auto it = events.find(id);
            if (it == events.end()) {
                continue;
            }
            Callback cb = std::move(it->second.cb);
            events.erase(it);
            try {
                if (cb) cb();
            } catch (...) {
                // Asio propagates handler exceptions out of io_context::run().
                // Isolate owner callbacks so one failed timeout cannot skip
                // later callbacks. Scheduler infrastructure failures still
                // propagate to the process runtime failure boundary.
            }
            if (released) {
                break;
            }
        }
        dispatching_ready_batch = false;
        ready.clear();

        if (!released && maintenance_callback &&
            maintenance_deadline <= std::chrono::steady_clock::now()) {
            maintenance_deadline = std::chrono::steady_clock::time_point::max();
            maintenance_callback(maintenance_owner);
        }
        if (!released) {
            MaybeCompactHeap();
            ArmTimer();
        }
    }

    void Release() noexcept {
        released = true;
        maintenance_deadline = std::chrono::steady_clock::time_point::max();
        maintenance_owner = nullptr;
        maintenance_callback = nullptr;
        RequestWakeup();
        dispatching_ready_batch = false;
        events.clear();
        deadline_heap.clear();
        ready_event_ids.clear();
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
        : asio::execution_context::service(ctx)
        , scheduler_(static_cast<net::io_context&>(ctx)) {}

    [[nodiscard]] TimeoutScheduler& Scheduler() noexcept {
        return scheduler_;
    }

    void ShutdownNow() noexcept {
        ClearThreadCache();
        scheduler_.Release();
    }

private:
    void ClearThreadCache() noexcept {
        if (tl_cached_scheduler == &scheduler_) {
            tl_cached_context = nullptr;
            tl_cached_scheduler = nullptr;
        }
    }

    void shutdown() override {
        ClearThreadCache();
        scheduler_.Release();
    }

    TimeoutScheduler scheduler_;
};

asio::execution_context::id TimeoutSchedulerService::id;

TimeoutScheduler::TimeoutScheduler(net::io_context& io_context)
    : impl_(std::make_unique<Impl>(io_context)) {}

TimeoutToken::~TimeoutToken() noexcept {
    if (Valid()) {
        owner_->Cancel(*this);
    }
}

TimeoutToken& TimeoutToken::operator=(TimeoutToken&& other) noexcept {
    if (this != &other) {
        if (Valid()) {
            owner_->Cancel(*this);
        }
        id_ = std::exchange(other.id_, 0);
        owner_ = std::exchange(other.owner_, nullptr);
    }
    return *this;
}

TimeoutScheduler& TimeoutScheduler::ForIoContext(net::io_context& io_context) {
    if (tl_cached_context == &io_context && tl_cached_scheduler) {
        return *tl_cached_scheduler;
    }

    auto& service = asio::use_service<TimeoutSchedulerService>(io_context);
    auto* ptr = &service.Scheduler();
    tl_cached_context = &io_context;
    tl_cached_scheduler = ptr;
    return *ptr;
}

void TimeoutScheduler::ReleaseForIoContext(net::io_context& io_context) {
    if (tl_cached_context == &io_context) {
        tl_cached_context = nullptr;
        tl_cached_scheduler = nullptr;
    }

    if (!asio::has_service<TimeoutSchedulerService>(io_context)) {
        return;
    }
    auto& service = asio::use_service<TimeoutSchedulerService>(io_context);
    service.ShutdownNow();
}

void TimeoutScheduler::Release() noexcept {
    impl_->Release();
}

TimeoutToken TimeoutScheduler::ScheduleAfter(
    std::chrono::milliseconds delay,
    Callback cb) {
    if (impl_->released) {
        return {};
    }

    if (delay < std::chrono::milliseconds::zero()) {
        delay = std::chrono::milliseconds::zero();
    }

    TimeoutToken token;
    token.id_ = impl_->next_id++;
    token.owner_ = this;
    using Clock = std::chrono::steady_clock;
    const auto now = Clock::now();
    const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
        Clock::time_point::max() - now);
    const auto deadline = delay >= remaining
        ? Clock::time_point::max() : now + delay;

    impl_->events.emplace(token.id_, Impl::Event{deadline, std::move(cb)});
    impl_->PushHeap(Impl::HeapEntry{deadline, token.id_});
    impl_->ArmTimer();

    return token;
}

bool TimeoutScheduler::SetMaintenanceDeadline(
    void* owner, void (*callback)(void*) noexcept,
    std::chrono::steady_clock::time_point deadline) {
    if (impl_->released) return false;
    if (!owner || !callback ||
        (impl_->maintenance_owner && impl_->maintenance_owner != owner)) {
        throw std::logic_error("timeout maintenance owner conflict");
    }
    impl_->maintenance_owner = owner;
    impl_->maintenance_callback = callback;
    impl_->maintenance_deadline = deadline;
    impl_->ArmTimer();
    return true;
}

void TimeoutScheduler::CancelMaintenance(void* owner) noexcept {
    if (impl_->maintenance_owner != owner) return;
    impl_->maintenance_deadline = std::chrono::steady_clock::time_point::max();
    impl_->maintenance_owner = nullptr;
    impl_->maintenance_callback = nullptr;
    impl_->ReconcileTimerAfterCancellation();
}

void TimeoutScheduler::Cancel(TimeoutToken& token) noexcept {
    if (!token.Valid()) return;
    if (token.owner_ != this) {
        return;
    }

    const uint64_t id = token.id_;
    token.Reset();
    if (!impl_->released) {
        const bool removed = impl_->events.erase(id) != 0;
        if (removed) {
            impl_->ReconcileTimerAfterCancellation();
            impl_->MaybeCompactHeap();
        }
    }
}

}  // namespace acpp
