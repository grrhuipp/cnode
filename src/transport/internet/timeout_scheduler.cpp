#include "acppnode/transport/internet/timeout_scheduler.hpp"
#include "acppnode/common/allocator.hpp"

#include <asio/steady_timer.hpp>
#include <mutex>
#include <unordered_map>

namespace acpp {

namespace {

constexpr auto kScanInterval = std::chrono::seconds(1);

}  // namespace

struct TimeoutScheduler::Impl {
    explicit Impl(net::io_context& io_context)
        : timer(io_context) {}

    struct Event {
        std::chrono::steady_clock::time_point deadline;
        Callback cb;
    };

    net::steady_timer timer;
    using TimeoutEventMap = memory::ThreadLocalUnorderedMap<uint64_t, Event>;

    TimeoutEventMap events;
    memory::ThreadLocalVector<Callback> ready_callbacks;
    uint64_t next_id = 1;
    bool timer_armed = false;

    void ArmTimer() {
        if (timer_armed || events.empty()) {
            return;
        }

        timer.expires_after(kScanInterval);
        timer_armed = true;
        timer.async_wait([this](const IoErrorCode& ec) {
            OnTimer(ec);
        });
    }

    void OnTimer(const IoErrorCode& ec) {
        timer_armed = false;
        if (ec) return;  // cancelled / stopped

        auto& ready = ready_callbacks;
        ready.clear();

        const auto now = std::chrono::steady_clock::now();
        for (auto it = events.begin(); it != events.end();) {
            if (it->second.deadline > now) {
                ++it;
                continue;
            }

            ready.push_back(std::move(it->second.cb));
            it = events.erase(it);
        }

        for (auto& cb : ready) {
            if (cb) cb();
        }
        ready.clear();

        ArmTimer();
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
    impl_->ArmTimer();

    return token;
}

void TimeoutScheduler::Cancel(TimeoutToken& token) {
    if (!token.Valid()) return;

    impl_->events.erase(token.id);
    token.Reset();
}

}  // namespace acpp
