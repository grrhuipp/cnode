#pragma once

#include "common/asio_types.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>


namespace transport {

class TimeoutSchedulerService;
class TimeoutScheduler;
// An event embedded in its owner, never separately allocated.
// Its address is stable from scheduling through cancellation/completion. An
// expiry detaches it before calling OnTimeout, which may rearm or destroy it.
class TimeoutEvent {
public:
    TimeoutEvent() noexcept = default;
    explicit TimeoutEvent(net::io_context& context) noexcept;
    TimeoutEvent(const TimeoutEvent&) = delete;
    TimeoutEvent& operator=(const TimeoutEvent&) = delete;
    TimeoutEvent(TimeoutEvent&&) = delete;
    TimeoutEvent& operator=(TimeoutEvent&&) = delete;

    [[nodiscard]] bool Valid() const noexcept { return owner_ != nullptr; }
    [[nodiscard]] bool ScheduleAfter(std::chrono::milliseconds delay);
    void Cancel() noexcept;

protected:
    ~TimeoutEvent() noexcept;
    virtual void OnTimeout() = 0;

private:
    friend class TimeoutScheduler;
    net::io_context* context_ = nullptr;
    TimeoutScheduler* owner_ = nullptr;
    std::chrono::steady_clock::time_point deadline_{};
    uint64_t sequence_ = 0;
    std::size_t index_ = 0;
};

// One indexed heap and native timer per Worker reactor.
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
    // Detach all events and join any in-flight native timer cancellation.
    static net::awaitable<void> AsyncReleaseForIoContext(net::io_context& io_context);

    // Rearming an existing event reuses its heap slot. False means released.
    // Failure leaves this event unarmed; unrelated events remain scheduled.
    [[nodiscard]] bool ScheduleAfter(std::chrono::milliseconds delay, TimeoutEvent& event);
    void Cancel(TimeoutEvent& event) noexcept;

    [[nodiscard]] ResourceStats GetResourceStats() const noexcept;

private:
    friend class TimeoutSchedulerService;
    friend class TimeoutEvent;
    explicit TimeoutScheduler(net::io_context& io_context);
    void Release() noexcept;
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace transport

