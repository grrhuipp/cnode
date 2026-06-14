#include "acppnode/transport/internet/timeout_scheduler.hpp"
#include "acppnode/common/allocator.hpp"

#include <algorithm>
#include <asio/steady_timer.hpp>
#include <mutex>
#include <queue>
#include <unordered_map>

namespace acpp {

namespace {

struct TimeoutQueueItem {
    std::chrono::steady_clock::time_point deadline;
    uint64_t id = 0;
};

struct TimeoutQueueItemCmp {
    bool operator()(const TimeoutQueueItem& a, const TimeoutQueueItem& b) const noexcept {
        if (a.deadline != b.deadline) return a.deadline > b.deadline;
        return a.id > b.id;
    }
};

}  // namespace

struct TimeoutScheduler::Impl {
    explicit Impl(net::io_context& io_context)
        : timer(io_context) {}

    struct Event {
        std::chrono::steady_clock::time_point deadline;
        Callback cb;
    };

    net::steady_timer timer;
    using TimeoutHeapStorage = memory::ThreadLocalVector<TimeoutQueueItem>;
    using TimeoutEventMap = memory::ThreadLocalUnorderedMap<uint64_t, Event>;

    std::priority_queue<TimeoutQueueItem, TimeoutHeapStorage, TimeoutQueueItemCmp> heap;
    TimeoutEventMap events;
    memory::ThreadLocalVector<Callback> ready_callbacks;
    uint64_t next_id = 1;
    bool timer_armed = false;

    void MaybeCompact() {
        // 惰性删除在高 churn 场景下会让大量已取消事件滞留在堆中，
        // 长时间高并发运行会放大内存和调度开销；比值过大时重建堆。
        constexpr size_t kMinHeapSizeForCompact = 4096;
        constexpr size_t kCompactRatio = 4;

        const size_t live = events.size();
        const size_t heap_size = heap.size();
        if (heap_size < kMinHeapSizeForCompact) {
            return;
        }

        const size_t baseline = std::max<size_t>(live, 1);
        if (heap_size <= baseline * kCompactRatio) {
            return;
        }

        std::priority_queue<TimeoutQueueItem, TimeoutHeapStorage, TimeoutQueueItemCmp>
            compacted;
        for (const auto& [id, event] : events) {
            compacted.push(TimeoutQueueItem{event.deadline, id});
        }
        heap.swap(compacted);
    }

    void ArmTimer() {
        while (!heap.empty()) {
            const auto item = heap.top();
            auto it = events.find(item.id);
            if (it == events.end() || it->second.deadline != item.deadline) {
                heap.pop();
                continue;
            }

            timer.expires_at(item.deadline);
            timer_armed = true;
            timer.async_wait([this](const IoErrorCode& ec) {
                OnTimer(ec);
            });
            return;
        }
        timer_armed = false;
    }

    void OnTimer(const IoErrorCode& ec) {
        if (ec) return;  // cancelled / stopped

        auto& ready = ready_callbacks;
        ready.clear();
        timer_armed = false;

        const auto now = std::chrono::steady_clock::now();
        while (!heap.empty()) {
            const auto item = heap.top();
            auto it = events.find(item.id);
            if (it == events.end() || it->second.deadline != item.deadline) {
                heap.pop();
                continue;
            }
            if (item.deadline > now) break;

            ready.push_back(std::move(it->second.cb));
            events.erase(it);
            heap.pop();
        }

        ArmTimer();
        MaybeCompact();

        for (auto& cb : ready) {
            if (cb) cb();
        }
        ready.clear();
    }
};

namespace {

std::mutex& SchedulerMutex() {
    static std::mutex mu;
    return mu;
}

auto& SchedulerShards() {
    static std::unordered_map<net::io_context*, std::unique_ptr<TimeoutScheduler>> shards;
    return shards;
}

thread_local net::io_context* tl_cached_context = nullptr;
thread_local TimeoutScheduler* tl_cached_scheduler = nullptr;

}  // namespace

TimeoutScheduler::TimeoutScheduler(net::io_context& io_context)
    : impl_(std::make_unique<Impl>(io_context)) {}

TimeoutScheduler& TimeoutScheduler::ForIoContext(net::io_context& io_context) {
    if (tl_cached_context == &io_context && tl_cached_scheduler) {
        return *tl_cached_scheduler;
    }

    std::lock_guard lk(SchedulerMutex());
    auto& shards = SchedulerShards();
    auto it = shards.find(&io_context);
    if (it != shards.end()) {
        tl_cached_context = &io_context;
        tl_cached_scheduler = it->second.get();
        return *it->second;
    }

    auto shard = std::unique_ptr<TimeoutScheduler>(new TimeoutScheduler(io_context));
    auto* ptr = shard.get();
    shards.emplace(&io_context, std::move(shard));
    tl_cached_context = &io_context;
    tl_cached_scheduler = ptr;
    return *ptr;
}

void TimeoutScheduler::ReleaseForIoContext(net::io_context& io_context) {
    if (tl_cached_context == &io_context) {
        tl_cached_context = nullptr;
        tl_cached_scheduler = nullptr;
    }

    std::unique_ptr<TimeoutScheduler> shard;
    {
        std::lock_guard lk(SchedulerMutex());
        auto& shards = SchedulerShards();
        auto it = shards.find(&io_context);
        if (it == shards.end()) {
            return;
        }
        shard = std::move(it->second);
        shards.erase(it);
    }
}

TimeoutToken TimeoutScheduler::ScheduleAfter(
    std::chrono::milliseconds delay,
    Callback cb) {
    if (delay < std::chrono::milliseconds::zero()) {
        delay = std::chrono::milliseconds::zero();
    }

    TimeoutToken token;
    token.id = impl_->next_id++;
    const auto deadline = std::chrono::steady_clock::now() + delay;

    impl_->events.insert_or_assign(token.id, Impl::Event{deadline, std::move(cb)});
    impl_->heap.push(TimeoutQueueItem{deadline, token.id});

    bool need_rearm = !impl_->timer_armed;
    if (!need_rearm) {
        need_rearm = deadline < impl_->timer.expiry();
    }
    if (need_rearm) {
        impl_->timer.cancel();
        impl_->timer_armed = false;
        impl_->ArmTimer();
    }

    return token;
}

void TimeoutScheduler::Cancel(TimeoutToken& token) {
    if (!token.Valid()) return;

    impl_->events.erase(token.id);
    impl_->MaybeCompact();
    token.Reset();
}

}  // namespace acpp
