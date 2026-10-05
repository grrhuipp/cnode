#pragma once

#include "acppnode/common/asio_types.hpp"
#include "acppnode/transport/internet/timeout_scheduler.hpp"

#include <asio/as_tuple.hpp>
#include <asio/experimental/channel.hpp>
#include <asio/use_awaitable.hpp>
#include <chrono>
#include <stdexcept>

namespace acpp {

// A pending delay uses the shared deadline service, never a resident timer.
// The owner must outlive WaitFor and its cancellation completion.
class AsyncDelay {
public:
    explicit AsyncDelay(net::any_io_executor executor)
        : executor_(std::move(executor)), scheduler_(TimeoutScheduler::ForExecutor(executor_)),
          signal_(executor_, 1) {}
    AsyncDelay(const AsyncDelay&) = delete;
    AsyncDelay& operator=(const AsyncDelay&) = delete;
    ~AsyncDelay() noexcept { scheduler_.Cancel(token_); }

    [[nodiscard]] net::awaitable<void> WaitFor(std::chrono::milliseconds delay) {
        if (delay <= std::chrono::milliseconds::zero()) co_return;
        if (waiting_) throw std::logic_error("AsyncDelay permits one pending wait");
        waiting_ = true;
        try {
            token_ = scheduler_.ScheduleAfter(delay, executor_, [this] {
                (void)signal_.try_send(IoErrorCode{});
            });
            auto [ec] = co_await signal_.async_receive(net::as_tuple(net::use_awaitable));
            scheduler_.Cancel(token_);
            if (ec && ec != io_error::operation_aborted) throw IoSystemError(ec);
        } catch (...) {
            scheduler_.Cancel(token_);
            waiting_ = false;
            throw;
        }
        waiting_ = false;
    }
    void Cancel() noexcept {
        scheduler_.Cancel(token_);
        if (waiting_) (void)signal_.try_send(IoErrorCode{});
    }
private:
    net::any_io_executor executor_;
    TimeoutScheduler& scheduler_;
    net::experimental::channel<void(IoErrorCode)> signal_;
    TimeoutToken token_;
    bool waiting_ = false;
};

}  // namespace acpp
