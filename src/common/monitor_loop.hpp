#pragma once

#include "common/error.hpp"

#include <asio/co_spawn.hpp>
#include <asio/bind_cancellation_slot.hpp>
#include <asio/cancellation_signal.hpp>
#include <asio/this_coro.hpp>
#include <asio/as_tuple.hpp>
#include <asio/steady_timer.hpp>
#include <asio/use_awaitable.hpp>

#include <exception>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <utility>

namespace monitor_detail {

// Each process or panel monitor has its own completion boundary. The factory owns its
// context, and co_spawn retains this state until this loop's exit is reported.
// Construction, Start, stop, join and completion belong to the main executor.
class MonitorLoop final : public std::enable_shared_from_this<MonitorLoop> {
public:
    using Factory = std::function<net::awaitable<void>()>;
    using ReportExit = std::function<void(std::string_view, std::exception_ptr)>;

    MonitorLoop(net::any_io_executor executor, std::string name,
                Factory factory, ReportExit report_exit)
        : executor_(std::move(executor)), name_(std::move(name)),
          factory_(std::move(factory)), report_exit_(std::move(report_exit)),
          completion_(executor_, net::steady_timer::time_point::max()) {}

    MonitorLoop(const MonitorLoop&) = delete;
    MonitorLoop& operator=(const MonitorLoop&) = delete;

    void Start() {
        if (active_ || stopping_) return;
        auto self = shared_from_this();
        active_ = true;
        try {
            net::co_spawn(executor_,
                [self]() -> net::awaitable<void> {
                    if (!self->stopping_) co_await self->factory_();
                },
                net::bind_cancellation_slot(cancellation_.slot(),
                    [self](std::exception_ptr failure) {
                        self->active_ = false;
                        self->completion_.cancel();
                        if (self->stopping_ && (!failure || IsOperationCancelled(failure))) return;
                        self->report_exit_(self->name_, std::move(failure));
                    }));
        } catch (...) {
            active_ = false;
            throw;
        }
    }

    void RequestStop() noexcept {
        if (stopping_) return;
        stopping_ = true;
        cancellation_.emit(net::cancellation_type::all);
    }

    net::awaitable<void> AsyncJoin() {
        // A cancelled owner still has to retain the loop through actual completion.
        co_await net::this_coro::reset_cancellation_state(net::disable_cancellation());
        while (active_) {
            (void)co_await completion_.async_wait(net::as_tuple(net::use_awaitable));
        }
    }


private:
    net::any_io_executor executor_;
    std::string name_;
    Factory factory_;
    ReportExit report_exit_;
    bool active_ = false;
    net::cancellation_signal cancellation_;
    net::steady_timer completion_;
    bool stopping_ = false;
};

}  // namespace monitor_detail
