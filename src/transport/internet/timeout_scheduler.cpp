#include "acppnode/transport/internet/timeout_scheduler.hpp"
#include "acppnode/common/allocator.hpp"
#include "acppnode/runtime/channel.hpp"

#include <algorithm>
#include <atomic>
#include <asio/bind_cancellation_slot.hpp>
#include <asio/co_spawn.hpp>
#include <asio/execution_context.hpp>
#include <asio/post.hpp>
#include <asio/steady_timer.hpp>
#include <asio/strand.hpp>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <unordered_map>
#include <vector>

namespace acpp {

struct TimeoutToken::State {
    TimeoutScheduler* owner = nullptr;
    std::weak_ptr<void> lifetime;
    uint64_t id = 0;
    std::shared_ptr<void> admission;
    TimeoutScheduler::Callback callback;
    bool active = true;
};

struct TimeoutScheduler::Impl {
    struct AdmissionCounter { std::atomic<std::size_t> outstanding{0}; };
    struct Admission {
        explicit Admission(std::shared_ptr<AdmissionCounter> counter) : counter(std::move(counter)) {}
        ~Admission() { counter->outstanding.fetch_sub(1, std::memory_order_release); }
        std::shared_ptr<AdmissionCounter> counter;
    };
    struct Event {
        std::chrono::steady_clock::time_point deadline;
        net::any_io_executor callback_executor;
        std::weak_ptr<TimeoutToken::State> state;
        std::shared_ptr<Admission> admission;
    };
    struct HeapEntry {
        std::chrono::steady_clock::time_point deadline;
        uint64_t id;
    };
    struct Compare {
        bool operator()(const HeapEntry& a, const HeapEntry& b) const noexcept {
            return a.deadline == b.deadline ? a.id > b.id : a.deadline > b.deadline;
        }
    };
    explicit Impl(net::any_io_executor executor)
        : executor(net::make_strand(std::move(executor))), timer(this->executor), observations(this->executor, 64) {
        events.reserve(1024);
        heap.reserve(1024);
    }

    net::any_io_executor executor;
    net::steady_timer timer;
    std::unordered_map<uint64_t, Event> events;
    std::vector<HeapEntry> heap;
    ServiceChannel observations;
    std::shared_ptr<AdmissionCounter> counter = std::make_shared<AdmissionCounter>();
    std::atomic<uint64_t> next_id{1};
    bool wait_pending = false;
    bool wakeup_requested = false;
    bool released = false;
    std::chrono::steady_clock::time_point armed_deadline{};

    [[nodiscard]] std::shared_ptr<Admission> Reserve() {
        auto count = counter->outstanding.load(std::memory_order_relaxed);
        do {
            if (count >= kCapacity) throw std::length_error("timeout scheduler capacity exhausted");
        } while (!counter->outstanding.compare_exchange_weak(count, count + 1,
            std::memory_order_acquire, std::memory_order_relaxed));
        try { return memory::AllocateShared<Admission>(counter); }
        catch (...) { counter->outstanding.fetch_sub(1, std::memory_order_release); throw; }
    }
    void Prune() {
        while (!heap.empty()) {
            auto it = events.find(heap.front().id);
            if (it != events.end() && it->second.deadline == heap.front().deadline) break;
            std::pop_heap(heap.begin(), heap.end(), Compare{});
            heap.pop_back();
        }
    }
    void Compact() noexcept {
        if (heap.size() <= events.size() + 1024 || heap.size() < events.size() * 2) return;
        std::erase_if(heap, [this](const HeapEntry& entry) {
            auto it = events.find(entry.id);
            return it == events.end() || it->second.deadline != entry.deadline;
        });
        std::make_heap(heap.begin(), heap.end(), Compare{});
    }
    void Wake() noexcept {
        if (!wait_pending || wakeup_requested) return;
        IoErrorCode ignored;
        timer.cancel(ignored);
        wakeup_requested = true;
    }
    void Arm() {
        Prune();
        if (heap.empty()) { Wake(); return; }
        const auto first = heap.front().deadline;
        if (wait_pending) { if (first < armed_deadline) Wake(); return; }
        timer.expires_at(first);
        timer.async_wait([this](IoErrorCode ec) { OnTimer(ec); });
        armed_deadline = first;
        wait_pending = true;
        wakeup_requested = false;
    }
    void OnTimer(IoErrorCode ec) {
        wait_pending = wakeup_requested = false;
        if (released) return;
        if (ec && ec != io_error::operation_aborted) throw IoSystemError(ec);
        const auto now = std::chrono::steady_clock::now();
        for (std::size_t batch = 0; batch < 64; ++batch) {
            Prune();
            if (heap.empty() || heap.front().deadline > now) break;
            const auto id = heap.front().id;
            std::pop_heap(heap.begin(), heap.end(), Compare{});
            heap.pop_back();
            auto node = events.extract(id);
            if (node.empty()) continue;
            auto event = std::move(node.mapped());
            net::post(event.callback_executor,
                [state = std::move(event.state), admission = std::move(event.admission)]() mutable {
                    if (auto handle = state.lock(); handle && handle->active) {
                        handle->active = false;
                        auto callback_admission = std::move(handle->admission);
                        auto callback = std::move(handle->callback);
                        try { if (callback) callback(); } catch (...) {}
                    }
                });
        }
        Compact();
        Arm();
    }
    void Insert(uint64_t id, Event event) {
        if (released) return;
        const auto deadline = event.deadline;
        events.emplace(id, std::move(event));
        try {
            heap.push_back({deadline, id});
            std::push_heap(heap.begin(), heap.end(), Compare{});
            Arm();
        } catch (...) { events.erase(id); throw; }
    }
    void Erase(uint64_t id) noexcept {
        events.erase(id);
        Prune();
        Compact();
        if (heap.empty()) Wake();
    }
    void Release() noexcept {
        released = true;
        Wake();
        events.clear();
        heap.clear();
    }
};

class TimeoutSchedulerService final : public asio::execution_context::service {
public:
    static asio::execution_context::id id;
    explicit TimeoutSchedulerService(asio::execution_context& context)
        : service(context) {}

    void Install(net::any_io_executor shared_executor) {
        std::lock_guard lock(mutex_);
        if (scheduler_) {
            if (*shared_executor_ != shared_executor)
                throw std::logic_error("timeout scheduler cannot be rebound to another executor");
            return;
        }
        shared_executor_ = shared_executor;
        scheduler_ = std::unique_ptr<TimeoutScheduler>(
            new TimeoutScheduler(std::move(shared_executor)));
    }

    TimeoutScheduler& Get() {
        std::lock_guard lock(mutex_);
        if (!scheduler_)
            throw std::logic_error("timeout scheduler is not installed");
        return *scheduler_;
    }

    void Release() noexcept {
        std::lock_guard lock(mutex_);
        if (scheduler_) scheduler_->Release();
    }

private:
    void shutdown() override {
        std::lock_guard lock(mutex_);
        if (scheduler_) scheduler_->Release();
        scheduler_.reset();
        shared_executor_.reset();
    }

    std::mutex mutex_;
    std::optional<net::any_io_executor> shared_executor_;
    std::unique_ptr<TimeoutScheduler> scheduler_;
};
asio::execution_context::id TimeoutSchedulerService::id;

TimeoutScheduler::TimeoutScheduler(net::any_io_executor executor)
    : impl_(std::make_shared<Impl>(std::move(executor))) {}

void TimeoutScheduler::Install(net::any_io_executor shared_executor) {
    auto& service = asio::use_service<TimeoutSchedulerService>(shared_executor.context());
    service.Install(std::move(shared_executor));
}
TimeoutScheduler& TimeoutScheduler::ForExecutor(net::any_io_executor executor) {
    return asio::use_service<TimeoutSchedulerService>(executor.context()).Get();
}
void TimeoutScheduler::ReleaseForExecutor(net::any_io_executor executor) noexcept {
    if (asio::has_service<TimeoutSchedulerService>(executor.context()))
        asio::use_service<TimeoutSchedulerService>(executor.context()).Release();
}
void TimeoutScheduler::Release() noexcept { impl_->Release(); }

TimeoutToken::~TimeoutToken() noexcept { Reset(); }
TimeoutToken::TimeoutToken(TimeoutToken&&) noexcept = default;
TimeoutToken& TimeoutToken::operator=(TimeoutToken&& other) noexcept {
    if (this != &other) { Reset(); state_ = std::move(other.state_); }
    return *this;
}
bool TimeoutToken::Valid() const noexcept { return state_ && state_->active; }
void TimeoutToken::Reset() noexcept {
    if (state_ && !state_->lifetime.expired()) state_->owner->Cancel(*this);
    else state_.reset();
}

TimeoutToken TimeoutScheduler::ScheduleAfter(std::chrono::milliseconds delay,
    net::any_io_executor callback_executor, Callback callback) {
    auto admission = impl_->Reserve();
    auto state = memory::AllocateShared<TimeoutToken::State>();
    state->admission = admission;
    state->owner = this;
    state->lifetime = impl_;
    state->id = impl_->next_id.fetch_add(1, std::memory_order_relaxed);
    state->callback = std::move(callback);
    delay = std::max(delay, std::chrono::milliseconds::zero());
    const auto now = std::chrono::steady_clock::now();
    const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::time_point::max() - now);
    const auto deadline = delay >= remaining ? std::chrono::steady_clock::time_point::max() : now + delay;
    net::post(impl_->executor, [impl = impl_.get(), id = state->id,
        event = Impl::Event{deadline, std::move(callback_executor), state, std::move(admission)}]() mutable {
        impl->Insert(id, std::move(event));
    });
    TimeoutToken token;
    token.state_ = std::move(state);
    return token;
}
void TimeoutScheduler::Cancel(TimeoutToken& token) noexcept {
    if (!token.state_ || token.state_->owner != this) return;
    auto state = std::move(token.state_);
    if (!std::exchange(state->active, false)) return;
    state->callback = {};
    // The reservation remains in the deadline command/event until this owned
    // cancellation executes. Failed allocation still invalidates the callback.
    try { net::post(impl_->executor, [impl = impl_.get(), id = state->id, admission = std::move(state->admission)] { impl->Erase(id); }); }
    catch (...) {}
}
net::awaitable<TimeoutScheduler::ResourceStats> TimeoutScheduler::GetResourceStats() {
    co_return co_await impl_->observations.Call([impl = impl_] {
        return ResourceStats{.active_events = impl->events.size(), .heap_entries = impl->heap.size(),
            .heap_capacity = impl->heap.capacity(), .event_buckets = impl->events.bucket_count(),
            .ready_events = 0, .wait_pending = impl->wait_pending};
    });
}

}  // namespace acpp
