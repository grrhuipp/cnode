#include "acppnode/transport/timeout_scheduler.hpp"

#include <queue>

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
    explicit Impl(net::any_io_executor ex)
        : executor(std::move(ex))
        , timer(executor) {}

    struct Event {
        std::chrono::steady_clock::time_point deadline;
        Callback cb;
    };

    net::any_io_executor executor;
    net::steady_timer timer;
    std::mutex mu;
    std::priority_queue<TimeoutQueueItem, std::vector<TimeoutQueueItem>, TimeoutQueueItemCmp> heap;
    std::unordered_map<uint64_t, Event> events;
    std::atomic<uint64_t> next_id{1};
    bool timer_armed = false;

    void ArmTimerLocked() {
        while (!heap.empty()) {
            const auto item = heap.top();
            auto it = events.find(item.id);
            if (it == events.end() || it->second.deadline != item.deadline) {
                heap.pop();
                continue;
            }

            timer.expires_at(item.deadline);
            timer_armed = true;
            timer.async_wait([this](const boost::system::error_code& ec) {
                OnTimer(ec);
            });
            return;
        }
        timer_armed = false;
    }

    void OnTimer(const boost::system::error_code& ec) {
        if (ec) return;  // cancelled / stopped

        std::vector<Callback> ready;
        {
            std::lock_guard lk(mu);
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

            ArmTimerLocked();
        }

        for (auto& cb : ready) {
            if (cb) cb();
        }
    }
};

TimeoutScheduler::TimeoutScheduler(net::any_io_executor executor)
    : impl_(std::make_unique<Impl>(std::move(executor))) {}

TimeoutScheduler& TimeoutScheduler::ForExecutor(net::any_io_executor executor) {
    static std::mutex g_mu;
    static std::unordered_map<void*, std::unique_ptr<TimeoutScheduler>> g_shards;

    auto& ctx = net::query(executor, net::execution::context);
    void* key = std::addressof(ctx);

    std::lock_guard lk(g_mu);
    auto it = g_shards.find(key);
    if (it != g_shards.end()) {
        return *it->second;
    }

    auto shard = std::unique_ptr<TimeoutScheduler>(new TimeoutScheduler(executor));
    auto* ptr = shard.get();
    g_shards.emplace(key, std::move(shard));
    return *ptr;
}

TimeoutToken TimeoutScheduler::ScheduleAfter(
    std::chrono::milliseconds delay,
    Callback cb) {
    if (delay < std::chrono::milliseconds::zero()) {
        delay = std::chrono::milliseconds::zero();
    }

    TimeoutToken token;
    token.id = impl_->next_id.fetch_add(1, std::memory_order_relaxed);
    const auto deadline = std::chrono::steady_clock::now() + delay;

    std::lock_guard lk(impl_->mu);
    impl_->events.insert_or_assign(token.id, Impl::Event{deadline, std::move(cb)});
    impl_->heap.push(TimeoutQueueItem{deadline, token.id});

    bool need_rearm = !impl_->timer_armed;
    if (!need_rearm) {
        need_rearm = deadline < impl_->timer.expiry();
    }
    if (need_rearm) {
        impl_->timer.cancel();
        impl_->timer_armed = false;
        impl_->ArmTimerLocked();
    }

    return token;
}

void TimeoutScheduler::Cancel(TimeoutToken& token) {
    if (!token.Valid()) return;

    std::lock_guard lk(impl_->mu);
    impl_->events.erase(token.id);
    token.Reset();
}

}  // namespace acpp
