#pragma once

#include "acppnode/common/asio_types.hpp"

#include <chrono>
#include <cstddef>
#include <memory>

namespace acpp {

class TimeoutSchedulerService;
class TimeoutScheduler;

// An owner-thread event embedded in its owner, never separately allocated.
// Its address is stable from scheduling through cancellation/completion. An
// expiry detaches it before calling OnTimeout, which may rearm or destroy it.
class TimeoutEvent {
public:
    TimeoutEvent() noexcept = default;
    TimeoutEvent(const TimeoutEvent&) = delete;
    TimeoutEvent& operator=(const TimeoutEvent&) = delete;
    TimeoutEvent(TimeoutEvent&&) = delete;
    TimeoutEvent& operator=(TimeoutEvent&&) = delete;

    [[nodiscard]] bool Valid() const noexcept { return owner_ != nullptr; }
    void Cancel() noexcept;

protected:
    ~TimeoutEvent() noexcept;
    virtual void OnTimeout() = 0;

private:
    friend class TimeoutScheduler;
    TimeoutScheduler* owner_ = nullptr;
    std::chrono::steady_clock::time_point deadline_{};
    std::size_t index_ = 0;
};

// The allocator's one maintenance wakeup must not inspect the scheduler's heap:
// it can be updated reentrantly while that heap's PMR storage is reallocating.
class TimeoutMaintenance {
protected:
    TimeoutMaintenance() noexcept = default;
    ~TimeoutMaintenance() = default;
    virtual void OnMaintenance() noexcept = 0;

private:
    friend class TimeoutScheduler;
};

// One owner-thread indexed heap and one outstanding timer per io_context.
// Heap entries borrow embedded events; cancellation removes an entry in place,
// with no event-map nodes, stale indices, callback allocations or ready list.
class TimeoutScheduler {
public:
    struct ResourceStats {
        std::size_t active_events = 0;
        std::size_t heap_capacity = 0;
        bool wait_pending = false;
    };

    [[nodiscard]] static TimeoutScheduler& ForIoContext(net::io_context& io_context);
    // Call on the owner after all users join; drain cancellation before
    // destroying the io_context and its PMR-backed scheduler service.
    static void ReleaseForIoContext(net::io_context& io_context);

    // Rearming an existing event reuses its heap slot. False means released.
    // Failure leaves this event unarmed; unrelated events remain scheduled.
    [[nodiscard]] bool ScheduleAfter(std::chrono::milliseconds delay, TimeoutEvent& event);
    void Cancel(TimeoutEvent& event) noexcept;

    [[nodiscard]] bool SetMaintenanceDeadline(
        TimeoutMaintenance& owner, std::chrono::steady_clock::time_point deadline);
    void CancelMaintenance(TimeoutMaintenance& owner) noexcept;

    [[nodiscard]] ResourceStats GetResourceStats() const noexcept;

private:
    friend class TimeoutSchedulerService;
    explicit TimeoutScheduler(net::io_context& io_context);
    void Release() noexcept;
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace acpp
