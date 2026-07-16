#include "acppnode/transport/internet/timeout_scheduler.hpp"
#include "acppnode/common/allocator.hpp"

#include <algorithm>
#include <asio/as_tuple.hpp>
#include <asio/execution_context.hpp>
#include <asio/steady_timer.hpp>
#include <asio/use_awaitable.hpp>

namespace acpp {

struct TimeoutScheduler::Impl {
    explicit Impl(net::io_context& io_context)
        : timer(io_context) {
        events.reserve(kInitialEventReserve);
        deadline_heap.reserve(kInitialEventReserve);
        ready_event_ids.reserve(kInitialReadyReserve);
    }

    static constexpr size_t kInitialEventReserve = 1024;
    static constexpr size_t kInitialReadyReserve = 64;

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
    uint64_t timer_generation = 0;
    bool timer_armed = false;
    bool released = false;
    std::chrono::steady_clock::time_point armed_deadline{};

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

    void ArmTimer() {
        PruneHeapTop();
        if (deadline_heap.empty()) {
            return;
        }

        const auto next_deadline = deadline_heap.front().deadline;

        if (timer_armed && next_deadline >= armed_deadline) {
            return;
        }

        const uint64_t generation = ++timer_generation;
        armed_deadline = next_deadline;
        timer_armed = true;
        timer.expires_at(next_deadline);
        timer.async_wait([this, generation](const IoErrorCode& ec) {
            if (generation != timer_generation) {
                return;
            }
            OnTimer(ec);
        });
    }

    void OnTimer(const IoErrorCode& ec) {
        timer_armed = false;
        if (released) return;
        if (ec) return;  // cancelled / stopped

        auto& ready = ready_event_ids;
        ready.clear();

        const auto now = std::chrono::steady_clock::now();
        while (true) {
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
        for (size_t i = 0; i < ready.size(); ++i) {
            const uint64_t id = ready[i];
            auto it = events.find(id);
            if (it == events.end()) {
                continue;
            }
            Callback cb = std::move(it->second.cb);
            events.erase(it);
            if (cb) cb();
            if (released) {
                break;
            }
        }
        ready.clear();

        if (!released) {
            ArmTimer();
        }
    }

    void Release() noexcept {
        released = true;
        ++timer_generation;
        IoErrorCode ec;
        timer.cancel(ec);
        timer_armed = false;
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
        scheduler_.Release();
    }

private:
    void shutdown() override {
        scheduler_.Release();
    }

    TimeoutScheduler scheduler_;
};

asio::execution_context::id TimeoutSchedulerService::id;

TimeoutScheduler::TimeoutScheduler(net::io_context& io_context)
    : impl_(std::make_unique<Impl>(io_context)) {}

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
    token.id = impl_->next_id++;
    const auto deadline = std::chrono::steady_clock::now() + delay;

    impl_->events.emplace(token.id, Impl::Event{deadline, std::move(cb)});
    impl_->PushHeap(Impl::HeapEntry{deadline, token.id});
    impl_->ArmTimer();

    return token;
}

void TimeoutScheduler::Cancel(TimeoutToken& token) {
    if (!token.Valid()) return;

    if (!impl_->released) {
        impl_->events.erase(token.id);
    }
    token.Reset();
}

ScheduledSleep::ScheduledSleep(net::io_context& io_context)
    : io_context_(io_context)
    , scheduler_(TimeoutScheduler::ForIoContext(io_context))
    , signal_(io_context, 1) {}

ScheduledSleep::~ScheduledSleep() noexcept {
    Cancel();
}

net::awaitable<void> ScheduledSleep::WaitFor(std::chrono::milliseconds delay) {
    if (delay <= std::chrono::milliseconds::zero()) {
        co_return;
    }

    Cancel();
    waiting_ = true;
    token_ = scheduler_.ScheduleAfter(delay, [this]() {
        token_.Reset();
        if (waiting_) {
            (void)signal_.try_send(IoErrorCode{});
        }
    });

    auto [ec] = co_await signal_.async_receive(net::as_tuple(net::use_awaitable));
    (void)ec;
    waiting_ = false;
}

void ScheduledSleep::Cancel() noexcept {
    if (token_.Valid()) {
        scheduler_.Cancel(token_);
    }
    if (waiting_) {
        (void)signal_.try_send(io_error::operation_aborted);
    }
}

}  // namespace acpp
