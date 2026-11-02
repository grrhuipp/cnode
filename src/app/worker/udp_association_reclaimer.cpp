#include "udp_association_reclaimer.hpp"

#include "acppnode/infra/runtime_failure.hpp"
#include "udp_ingress.hpp"

#include <algorithm>
#include <exception>
#include <utility>

namespace acpp::worker_detail {
namespace {
constexpr auto kInterval = std::chrono::milliseconds(100);
constexpr size_t kMaxChecks = 64;
}

UdpAssociationReclaimer::UdpAssociationReclaimer(
    TimeoutScheduler& scheduler, std::function<void(std::exception_ptr)> on_failure) noexcept
    : scheduler_(scheduler), on_failure_(std::move(on_failure)) {}

UdpAssociationReclaimer::~UdpAssociationReclaimer() noexcept { Stop(); }

void UdpAssociationReclaimer::Register(
    UdpAssociationHook& hook, UdpIngress& owner, std::string_view socket_key,
    const ClientSessionKey& client_key, std::chrono::seconds idle_timeout) noexcept {
    if (stopped_) {
        FailRuntime("udp-maintenance", "association registered after reclaimer stop");
    }
    if (hook.owner) {
        FailRuntime("udp-maintenance", "association hook registered twice");
    }
    hook.owner = &owner;
    hook.socket_key = socket_key;
    hook.client_key = &client_key;
    hook.idle_timeout = idle_timeout;
    hook.previous = nullptr;
    hook.next = head_;
    if (head_) head_->previous = &hook;
    head_ = &hook;
    ++rows_;
    if (!cursor_) cursor_ = &hook;
    Schedule();
}

void UdpAssociationReclaimer::Unregister(UdpAssociationHook& hook) noexcept {
    if (!hook.owner) return;
    if (hook.previous) hook.previous->next = hook.next;
    else head_ = hook.next;
    if (hook.next) hook.next->previous = hook.previous;
    if (cursor_ == &hook) cursor_ = hook.next ? hook.next : head_;
    --rows_;
    hook = {};
    if (!head_) {
        cursor_ = nullptr;
        scheduler_.Cancel(*this);
    }
}

void UdpAssociationReclaimer::Stop() noexcept {
    if (stopped_) return;
    stopped_ = true;
    scheduler_.Cancel(*this);
}

void UdpAssociationReclaimer::OnTimeout() noexcept {
    if (stopped_ || !head_) return;
    RunBatch();
    if (head_) {
        Schedule();
    }
}

void UdpAssociationReclaimer::Schedule() noexcept {
    if (stopped_ || failed_ || !head_ || Valid()) return;
    try {
        if (!scheduler_.ScheduleAfter(kInterval, *this))
            FailRuntime("udp-maintenance", "association schedule refused after release");
    } catch (...) {
        failed_ = true;
        on_failure_(std::current_exception());
    }
}

void UdpAssociationReclaimer::RunBatch() noexcept {
    last_batch_checks_ = 0;
    if (++batch_generation_ == 0) ++batch_generation_;
    const auto now = std::chrono::steady_clock::now();
    while (cursor_ && last_batch_checks_ < kMaxChecks &&
           cursor_->last_batch_generation != batch_generation_) {
        auto* row = cursor_;
        row->last_batch_generation = batch_generation_;
        // Advance before the owner can unlink and erase this map-embedded hook.
        cursor_ = row->next ? row->next : head_;
        row->owner->ReclaimAssociation(*row, now);
        ++last_batch_checks_;
    }
    max_batch_checks_ = std::max(max_batch_checks_, last_batch_checks_);
}

UdpAssociationReclaimer::Stats UdpAssociationReclaimer::GetStats() const noexcept {
    return Stats{
        .rows = rows_,
        .last_batch_checks = last_batch_checks_,
        .max_batch_checks = max_batch_checks_,
    };
}

} // namespace acpp::worker_detail
