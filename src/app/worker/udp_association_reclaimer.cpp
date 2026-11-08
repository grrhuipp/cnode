#include "udp_association_reclaimer.hpp"

#include "infra/runtime_failure.hpp"
#include "udp_ingress.hpp"

#include <algorithm>
#include <exception>
#include <utility>

namespace worker_detail {
namespace {
// Rows inspected per wake; further due rows wait for the next event-loop turn.
constexpr std::size_t kMaxChecks = 64;
}

UdpAssociationHook::TimePoint UdpAssociationExpiry(
    UdpAssociationHook::TimePoint last_active, std::chrono::seconds idle_timeout) noexcept {
    using TimePoint = UdpAssociationHook::TimePoint;
    if (idle_timeout <= std::chrono::seconds::zero()) return TimePoint::max();
    // Saturate instead of overflowing the clock: such a row never expires.
    if (idle_timeout >= std::chrono::duration_cast<std::chrono::seconds>(
            TimePoint::max() - last_active)) {
        return TimePoint::max();
    }
    return last_active + idle_timeout;
}

UdpAssociationReclaimer::UdpAssociationReclaimer(
    TimeoutScheduler& scheduler,
    void* failure_context,
    FailureCallback on_failure) noexcept
    : TimeoutEvent(TimeoutEvent::WorkerLocal{})
    , scheduler_(scheduler)
    , failure_context_(failure_context)
    , on_failure_(on_failure) {}

UdpAssociationReclaimer::~UdpAssociationReclaimer() noexcept { Stop(); }

void UdpAssociationReclaimer::ReserveRow() {
    if (heap_.size() < heap_.capacity()) return;
    heap_.reserve(std::max<std::size_t>(4, heap_.capacity() * 2));
}

void UdpAssociationReclaimer::Register(
    UdpAssociationHook& hook, UdpIngress& owner, std::string_view socket_key,
    const ClientSessionKey& client_key, std::chrono::seconds idle_timeout,
    TimePoint deadline) noexcept {
    if (stopped_) {
        FailRuntime("udp-maintenance", "association registered after reclaimer stop");
    }
    if (hook.owner) {
        FailRuntime("udp-maintenance", "association hook registered twice");
    }
    if (heap_.size() == heap_.capacity()) {
        FailRuntime("udp-maintenance", "association registered without reserved capacity");
    }
    hook.owner = &owner;
    hook.socket_key = socket_key;
    hook.client_key = &client_key;
    hook.idle_timeout = idle_timeout;
    hook.deadline = deadline;
    heap_.push_back(&hook);
    SiftUp(heap_.size() - 1);
    Schedule();
}

void UdpAssociationReclaimer::Rearm(UdpAssociationHook& hook, TimePoint deadline) noexcept {
    if (!hook.owner) return;
    hook.deadline = deadline;
    Repair(hook.heap_index);
    Schedule();
}

void UdpAssociationReclaimer::Unregister(UdpAssociationHook& hook) noexcept {
    if (!hook.owner) return;
    const auto index = hook.heap_index;
    auto* last = heap_.back();
    heap_.pop_back();
    if (index != heap_.size()) {
        Place(index, last);
        Repair(index);
    }
    hook = {};
    if (heap_.empty()) {
        scheduler_.Cancel(*this);
        // Idle Workers return the index storage to the pool.
        decltype(heap_)(heap_.get_allocator()).swap(heap_);
    }
}

void UdpAssociationReclaimer::Stop() noexcept {
    if (stopped_) return;
    stopped_ = true;
    scheduler_.Cancel(*this);
}

void UdpAssociationReclaimer::OnTimeout() noexcept {
    if (stopped_) return;
    const auto now = std::chrono::steady_clock::now();
    running_batch_ = true;
    // Re-read the head each time: reclaiming may synchronously unlink other rows.
    // The owner either unlinks the row or re-arms it no earlier than `now`.
    for (std::size_t checks = 0;
         checks < kMaxChecks && !heap_.empty() && heap_.front()->deadline < now; ++checks) {
        auto& row = *heap_.front();
        row.owner->ReclaimAssociation(row, now);
    }
    running_batch_ = false;
    Schedule();
}

void UdpAssociationReclaimer::Schedule() noexcept {
    if (stopped_ || failed_ || running_batch_) return;
    if (heap_.empty() || heap_.front()->deadline == TimePoint::max()) {
        scheduler_.Cancel(*this);
        return;
    }
    const auto deadline = heap_.front()->deadline;
    // A pending wake at or before the head is kept: a wake that finds nothing
    // due only re-arms, so the event is moved earlier, never pushed back.
    if (Valid() && armed_deadline_ <= deadline) return;
    const auto now = std::chrono::steady_clock::now();
    const auto delay = deadline <= now
        ? std::chrono::milliseconds::zero()
        : std::chrono::ceil<std::chrono::milliseconds>(deadline - now);
    try {
        if (!scheduler_.ScheduleAfter(delay, *this))
            FailRuntime("udp-maintenance", "association schedule refused after release");
        armed_deadline_ = deadline;
    } catch (...) {
        failed_ = true;
        if (on_failure_) on_failure_(failure_context_, std::current_exception());
    }
}

void UdpAssociationReclaimer::Place(std::size_t index, UdpAssociationHook* hook) noexcept {
    heap_[index] = hook;
    hook->heap_index = index;
}

void UdpAssociationReclaimer::SiftUp(std::size_t index) noexcept {
    auto* hook = heap_[index];
    while (index != 0) {
        const auto parent = (index - 1) / 2;
        if (!(hook->deadline < heap_[parent]->deadline)) break;
        Place(index, heap_[parent]);
        index = parent;
    }
    Place(index, hook);
}

void UdpAssociationReclaimer::SiftDown(std::size_t index) noexcept {
    auto* hook = heap_[index];
    const auto size = heap_.size();
    for (;;) {
        auto child = index * 2 + 1;
        if (child >= size) break;
        if (child + 1 < size && heap_[child + 1]->deadline < heap_[child]->deadline) ++child;
        if (!(heap_[child]->deadline < hook->deadline)) break;
        Place(index, heap_[child]);
        index = child;
    }
    Place(index, hook);
}

void UdpAssociationReclaimer::Repair(std::size_t index) noexcept {
    if (index != 0 && heap_[index]->deadline < heap_[(index - 1) / 2]->deadline) {
        SiftUp(index);
    } else {
        SiftDown(index);
    }
}

} // namespace worker_detail
