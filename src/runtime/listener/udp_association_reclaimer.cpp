#include "udp_association_reclaimer.hpp"

#include "udp_ingress.hpp"

#include <algorithm>
#include <exception>
#include <stdexcept>

namespace acpp::inbound_detail {
namespace {
constexpr auto kInterval = std::chrono::milliseconds(100);
constexpr size_t kMaxChecks = 64;
} // namespace

UdpAssociationReclaimer::UdpAssociationReclaimer(
    TimeoutScheduler &scheduler, net::any_io_executor owner_executor) noexcept
    : scheduler_(scheduler), owner_executor_(std::move(owner_executor)) {}

UdpAssociationReclaimer::~UdpAssociationReclaimer() noexcept { Stop(); }

void UdpAssociationReclaimer::Register(UdpAssociationHook &hook,
                                       UdpIngress &owner,
                                       std::string_view socket_key,
                                       std::string_view client_key,
                                       std::chrono::seconds idle_timeout) {
  if (stopped_) {
    if (failure_)
      std::rethrow_exception(failure_);
    throw std::logic_error("association registered after UDP reclaimer stop");
  }
  if (hook.owner) {
    throw std::logic_error("UDP association hook registered twice");
  }
  hook.owner = &owner;
  hook.socket_key = socket_key;
  hook.client_key = client_key;
  hook.idle_timeout = idle_timeout;
  hook.previous = nullptr;
  hook.next = head_;
  if (head_)
    head_->previous = &hook;
  head_ = &hook;
  ++rows_;
  if (!cursor_)
    cursor_ = &hook;
  try {
    Schedule();
  } catch (...) {
    Unregister(hook);
    throw;
  }
}

void UdpAssociationReclaimer::Unregister(UdpAssociationHook &hook) noexcept {
  if (!hook.owner)
    return;
  if (hook.previous)
    hook.previous->next = hook.next;
  else
    head_ = hook.next;
  if (hook.next)
    hook.next->previous = hook.previous;
  if (cursor_ == &hook)
    cursor_ = hook.next ? hook.next : head_;
  --rows_;
  hook = {};
  if (!head_) {
    cursor_ = nullptr;
    scheduler_.Cancel(token_);
  }
}

void UdpAssociationReclaimer::Stop() noexcept {
  if (stopped_)
    return;
  stopped_ = true;
  scheduler_.Cancel(token_);
}

void UdpAssociationReclaimer::Tick(void *owner) noexcept {
  auto &self = *static_cast<UdpAssociationReclaimer *>(owner);
  self.token_.Reset();
  if (self.stopped_ || !self.head_)
    return;
  try {
    self.RunBatch();
    if (self.head_)
      self.Schedule();
  } catch (...) {
    self.RecordFailure(std::current_exception());
  }
}

void UdpAssociationReclaimer::Schedule() {
  if (stopped_ || !head_ || token_.Valid())
    return;
  token_ = scheduler_.ScheduleAfter(kInterval, owner_executor_,
                                    [this] { Tick(this); });
  if (!token_.Valid())
    throw std::runtime_error("UDP association reclaimer returned no token");
}

void UdpAssociationReclaimer::RecordFailure(
    std::exception_ptr failure) noexcept {
  if (!failure_)
    failure_ = std::move(failure);
  stopped_ = true;
  scheduler_.Cancel(token_);

  // Report to every ingress represented in the intrusive rows. Reporting a
  // failure stops that ingress and unlinks all of its rows, so the head must
  // advance on every iteration without allocating a temporary owner list.
  while (head_) {
    UdpIngress *const owner = head_->owner;
    if (!owner) {
      Unregister(*head_);
      continue;
    }
    owner->ReportBackgroundFailure(failure_);
  }
}

void UdpAssociationReclaimer::RunBatch() noexcept {
  last_batch_checks_ = 0;
  if (++batch_generation_ == 0)
    ++batch_generation_;
  const auto now = std::chrono::steady_clock::now();
  while (cursor_ && last_batch_checks_ < kMaxChecks &&
         cursor_->last_batch_generation != batch_generation_) {
    auto *row = cursor_;
    row->last_batch_generation = batch_generation_;
    // Advance before the owner can unlink and erase this map-embedded hook.
    cursor_ = row->next ? row->next : head_;
    row->owner->ReclaimAssociation(*row, now);
    ++last_batch_checks_;
  }
  max_batch_checks_ = std::max(max_batch_checks_, last_batch_checks_);
}

UdpAssociationReclaimer::Stats
UdpAssociationReclaimer::GetStats() const noexcept {
  return Stats{
      .rows = rows_,
      .last_batch_checks = last_batch_checks_,
      .max_batch_checks = max_batch_checks_,
  };
}

} // namespace acpp::inbound_detail
