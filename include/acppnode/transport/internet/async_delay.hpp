#pragma once

#include "acppnode/common/asio_types.hpp"
#include "acppnode/transport/internet/timeout_scheduler.hpp"

#include <asio/as_tuple.hpp>
#include <asio/bind_cancellation_slot.hpp>
#include <asio/experimental/channel.hpp>
#include <asio/this_coro.hpp>
#include <asio/use_awaitable.hpp>

#include <algorithm>
#include <chrono>
#include <stdexcept>

namespace acpp {

// One borrowed embedded event per active delay; no per-connection timer.
// The owner outlives WaitFor and joins it after cancellation.
class AsyncDelay final : private TimeoutEvent {
public:
    explicit AsyncDelay(net::io_context& io_context)
        : scheduler_(TimeoutScheduler::ForIoContext(io_context)), wake_(io_context, 0) {}
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
            // A finite far-future deadline reserves the scheduler's physical
            // wait even for an effectively infinite delay. Cancel then only
            // changes an existing heap entry and cancels that physical wait.
            using Clock = std::chrono::steady_clock;
            const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
                Clock::time_point::max() - Clock::now()) - std::chrono::milliseconds(1);
            if (!scheduler_.ScheduleAfter(std::min(delay, remaining), *this))
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
        if (waiting_ && Valid())
            (void)scheduler_.ScheduleAfter(std::chrono::milliseconds::zero(), *this);
    }

private:
    // Runs on the scheduler's executor. Dispatch completes the existing waiter
    // directly; channel.cancel/post would allocate another completion node.
    void OnTimeout() override { (void)wake_.try_send_via_dispatch(IoErrorCode{}); }
    TimeoutScheduler& scheduler_;
    SignalChannel wake_;
    bool waiting_ = false;
};

}  // namespace acpp
