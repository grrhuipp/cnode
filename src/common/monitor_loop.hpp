#pragma once

#include "acppnode/common/asio_types.hpp"

#include <asio/co_spawn.hpp>

#include <exception>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <utility>

namespace acpp::monitor_detail {

// Each process or panel monitor has its own completion boundary. The factory owns its
// context, and co_spawn retains this state until this loop's exit is reported.
// Construction, Start and completion all belong to the main io_context thread.
class MonitorLoop final : public std::enable_shared_from_this<MonitorLoop> {
public:
    using Factory = std::function<net::awaitable<void>()>;
    using ReportExit = std::function<void(std::string_view, std::exception_ptr)>;

    MonitorLoop(net::any_io_executor executor, std::string name,
                Factory factory, ReportExit report_exit)
        : executor_(std::move(executor)), name_(std::move(name)),
          factory_(std::move(factory)), report_exit_(std::move(report_exit)) {}

    MonitorLoop(const MonitorLoop&) = delete;
    MonitorLoop& operator=(const MonitorLoop&) = delete;

    void Start() {
        if (active_) return;
        auto self = shared_from_this();
        active_ = true;
        try {
            net::co_spawn(executor_,
                [self] { return self->factory_(); },
                [self](std::exception_ptr failure) {
                    self->active_ = false;
                    self->report_exit_(self->name_, std::move(failure));
                });
        } catch (...) {
            active_ = false;
            throw;
        }
    }

private:
    net::any_io_executor executor_;
    std::string name_;
    Factory factory_;
    ReportExit report_exit_;
    bool active_ = false;
};

}  // namespace acpp::monitor_detail
