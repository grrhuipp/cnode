#include "acppnode/transport/internet/timeout_scheduler.hpp"
#include "acppnode/common/allocator.hpp"

#include <asio/steady_timer.hpp>
#include <mutex>
#include <unordered_map>

namespace acpp {

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
    uint64_t timer_generation = 0;
    bool timer_armed = false;
    std::chrono::steady_clock::time_point armed_deadline{};

    void ArmTimer() {
        if (events.empty()) {
            return;
        }

        auto next_deadline = events.begin()->second.deadline;
        for (const auto& [id, event] : events) {
            (void)id;
            if (event.deadline < next_deadline) {
                next_deadline = event.deadline;
            }
        }

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
