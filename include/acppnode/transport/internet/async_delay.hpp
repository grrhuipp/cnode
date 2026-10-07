#pragma once

#include "acppnode/common/asio_types.hpp"

#include <asio/as_tuple.hpp>
#include <asio/steady_timer.hpp>
#include <asio/use_awaitable.hpp>

#include <chrono>
#include <stdexcept>

namespace acpp {

// One Worker-local pending delay. The owner must outlive WaitFor, including
// completion after cancellation. There is no callback registration or second
// wake channel: cancelling the actual wait needs no completion allocation.
class AsyncDelay {
public:
    explicit AsyncDelay(net::io_context& io_context) : timer_(io_context) {}

    AsyncDelay(const AsyncDelay&) = delete;
    AsyncDelay& operator=(const AsyncDelay&) = delete;

    // Cancellation ends the delay normally. Callers such as Mux then inspect
    // their terminal state; parent coroutine cancellation remains in effect.
    [[nodiscard]] net::awaitable<void> WaitFor(std::chrono::milliseconds delay) {
        if (delay <= std::chrono::milliseconds::zero()) co_return;
        if (waiting_) {
            throw std::logic_error("AsyncDelay does not support concurrent WaitFor calls");
        }
        waiting_ = true;
        try {
            using Clock = std::chrono::steady_clock;
            const auto now = Clock::now();
            const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
                Clock::time_point::max() - now);
            timer_.expires_at(delay >= remaining ? Clock::time_point::max() : now + delay);
            auto [ec] = co_await timer_.async_wait(net::as_tuple(net::use_awaitable));
            if (ec && ec != io_error::operation_aborted) throw IoSystemError(ec);
        } catch (...) {
            waiting_ = false;
            throw;
        }
        waiting_ = false;
    }

    void Cancel() noexcept {
        IoErrorCode ec;
        timer_.cancel(ec);
    }

private:
    net::steady_timer timer_;
    bool waiting_ = false;
};

}  // namespace acpp
