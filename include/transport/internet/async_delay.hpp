#pragma once

#include "common/asio_types.hpp"
#include "app/session_group_executor.hpp"
#include "transport/internet/timeout_scheduler.hpp"

#include <asio/as_tuple.hpp>
#include <asio/bind_cancellation_slot.hpp>
#include <asio/experimental/channel.hpp>
#include <asio/this_coro.hpp>
#include <asio/use_awaitable.hpp>

#include <chrono>
#include <stdexcept>


// One borrowed embedded event per active delay; no per-connection timer.
// The owner outlives WaitFor and joins it after cancellation.
class AsyncDelay final : private TimeoutEvent {
public:
    explicit AsyncDelay(net::io_context& io_context)
        : TimeoutEvent(io_context),
          wake_(ExecutionDomain::Current() ? ExecutionDomain::Current()->Executor()
              : net::any_io_executor(io_context.get_executor()), 0) {}
    AsyncDelay(const AsyncDelay&) = delete;
    AsyncDelay& operator=(const AsyncDelay&) = delete;

    // Cancellation expedites the existing event. Completion remains deferred
    // to the owner loop and needs no new cancellation-completion allocation.
    [[nodiscard]] net::awaitable<void> WaitFor(std::chrono::milliseconds delay) {
        if (delay <= std::chrono::milliseconds::zero()) co_return;
        if (waiting_) throw std::logic_error("AsyncDelay does not support concurrent WaitFor calls");
        auto cancellation = co_await net::this_coro::cancellation_state;
        if (cancellation.cancelled() != net::cancellation_type::none) co_return;
        auto slot = cancellation.slot();
        waiting_ = true;
        try {
            // The scheduler keeps a cancellable native wait even when this
            // duration saturates to the clock's maximum time point.
            if (!ScheduleAfter(delay))
                throw IoSystemError(io_error::operation_aborted);
            if (slot.is_connected()) slot.assign([this](net::cancellation_type_t) { Cancel(); });
            const auto [ec] = co_await wake_.async_receive(net::bind_cancellation_slot(
                net::cancellation_slot{}, net::as_tuple(net::use_awaitable)));
            if (slot.is_connected()) slot.clear();
            TimeoutEvent::Cancel();
            if (ec) throw IoSystemError(ec);
        } catch (...) {
            if (slot.is_connected()) slot.clear();
            TimeoutEvent::Cancel();
            waiting_ = false;
            throw;
        }
        waiting_ = false;
    }

    void Cancel() noexcept {
        if (!waiting_) return;
        try {
            if (Valid() && ScheduleAfter(std::chrono::milliseconds::zero())) return;
        } catch (...) {
            TimeoutEvent::Cancel();
        }
        // Domain failure/release can already have detached the event. The
        // waiter still needs its cancellation wakeup; its receive deliberately
        // does not use the parent's cancellation slot.
        (void)wake_.try_send_via_dispatch(IoErrorCode{});
    }

private:
    // Runs under the event's domain lease (or its fixed Worker for a control
    // delay). Dispatch completes the existing waiter without a completion node.
    void OnTimeout() override { (void)wake_.try_send_via_dispatch(IoErrorCode{}); }
    SignalChannel wake_;
    bool waiting_ = false;
};

