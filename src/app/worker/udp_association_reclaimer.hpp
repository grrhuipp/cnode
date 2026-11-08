#pragma once

#include "common/allocator.hpp"
#include "transport/internet/timeout_scheduler.hpp"

#include <chrono>
#include <cstddef>
#include <exception>
#include <string_view>

namespace worker_detail {

class UdpIngress;
struct ClientSessionKey;

// Embedded in an association row; its address is stable while registered.
struct UdpAssociationHook final {
    using TimePoint = std::chrono::steady_clock::time_point;

    UdpIngress* owner = nullptr;
    std::string_view socket_key;
    const ClientSessionKey* client_key = nullptr;
    std::chrono::seconds idle_timeout{};
    // Earliest instant the row may need reclaiming. Uplink activity does not
    // move it; a due open row is re-checked against its last activity and
    // re-armed. min() marks a closed row, max() an open row that never expires.
    TimePoint deadline{};
    std::size_t heap_index = 0;
};

// Idle expiry of a row last active at `last_active`; max() when disabled.
[[nodiscard]] UdpAssociationHook::TimePoint UdpAssociationExpiry(
    UdpAssociationHook::TimePoint last_active, std::chrono::seconds idle_timeout) noexcept;

// Worker-local min-heap over association rows embedded in UdpIngress maps.
// One maintenance event sleeps until the nearest row deadline and reclaims at
// most a bounded batch per wake; no timer runs while no row can expire.
class UdpAssociationReclaimer final : public memory::ThreadAllocated, private TimeoutEvent {
public:
    using FailureCallback = void (*)(void*, std::exception_ptr);
    using TimePoint = UdpAssociationHook::TimePoint;

    UdpAssociationReclaimer(TimeoutScheduler& scheduler,
                            void* failure_context,
                            FailureCallback on_failure) noexcept;
    ~UdpAssociationReclaimer() noexcept;
    UdpAssociationReclaimer(const UdpAssociationReclaimer&) = delete;
    UdpAssociationReclaimer& operator=(const UdpAssociationReclaimer&) = delete;

    // The only allocating step: call before inserting a row so Register
    // cannot fail once the row exists.
    void ReserveRow();
    void Register(UdpAssociationHook& hook, UdpIngress& owner,
                  std::string_view socket_key, const ClientSessionKey& client_key,
                  std::chrono::seconds idle_timeout, TimePoint deadline) noexcept;
    // Moves a registered row to a new deadline; unregistered hooks are ignored.
    void Rearm(UdpAssociationHook& hook, TimePoint deadline) noexcept;
    void Unregister(UdpAssociationHook& hook) noexcept;
    void Stop() noexcept;

private:
    void OnTimeout() noexcept override;
    void Schedule() noexcept;
    void Place(std::size_t index, UdpAssociationHook* hook) noexcept;
    void SiftUp(std::size_t index) noexcept;
    void SiftDown(std::size_t index) noexcept;
    void Repair(std::size_t index) noexcept;

    TimeoutScheduler& scheduler_;
    void* failure_context_ = nullptr;
    FailureCallback on_failure_ = nullptr;
    memory::ThreadLocalVector<UdpAssociationHook*> heap_;
    TimePoint armed_deadline_{};
    bool stopped_ = false;
    bool failed_ = false;
    bool running_batch_ = false;
};

} // namespace worker_detail
