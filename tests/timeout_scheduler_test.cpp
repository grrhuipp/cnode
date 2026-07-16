#include "acppnode/transport/internet/timeout_scheduler.hpp"

#include <chrono>
#include <stdexcept>
#include <thread>

int main() {
    using namespace std::chrono_literals;

    acpp::net::io_context io_context;
    auto& scheduler = acpp::TimeoutScheduler::ForIoContext(io_context);

    bool first_ran = false;
    bool cancelled_ran = false;
    acpp::TimeoutToken cancelled;

    auto first = scheduler.ScheduleAfter(1ms, [&]() {
        first_ran = true;
        scheduler.Cancel(cancelled);
    });
    cancelled = scheduler.ScheduleAfter(1ms, [&]() {
        cancelled_ran = true;
    });

    // Make both deadlines ready before the first timer handler collects its
    // batch. The first callback must still be able to cancel the second one.
    std::this_thread::sleep_for(10ms);
    io_context.run();

    if (!first_ran) {
        return 1;
    }
    if (cancelled_ran) {
        return 2;
    }
    if (cancelled.Valid()) {
        return 3;
    }

    scheduler.Cancel(first);

    bool after_throw_ran = false;
    auto throwing = scheduler.ScheduleAfter(1ms, []() {
        throw std::runtime_error("timeout callback failure");
    });
    auto after_throw = scheduler.ScheduleAfter(1ms, [&]() {
        after_throw_ran = true;
    });

    std::this_thread::sleep_for(10ms);
    io_context.restart();
    try {
        io_context.run();
    } catch (...) {
        return 4;
    }
    if (!after_throw_ran) {
        return 5;
    }

    scheduler.Cancel(throwing);
    scheduler.Cancel(after_throw);
    acpp::TimeoutScheduler::ReleaseForIoContext(io_context);
    return 0;
}
