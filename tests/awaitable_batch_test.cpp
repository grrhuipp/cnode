#include "awaitable_batch.hpp"

#include <asio/as_tuple.hpp>
#include <asio/co_spawn.hpp>
#include <asio/use_future.hpp>

#include <algorithm>
#include <chrono>
#include <stdexcept>
#include <vector>

namespace {

acpp::net::awaitable<void> TrackedTask(
    acpp::net::io_context& io_context,
    int& active,
    int& peak_active,
    int& completed,
    bool fail) {
    ++active;
    peak_active = std::max(peak_active, active);

    acpp::net::steady_timer timer(io_context);
    timer.expires_after(std::chrono::milliseconds(10));
    (void)co_await timer.async_wait(
        acpp::net::as_tuple(acpp::net::use_awaitable));

    --active;
    ++completed;
    if (fail) {
        throw std::runtime_error("expected batch failure");
    }
}

}  // namespace

int main() {
    acpp::net::io_context io_context;
    int active = 0;
    int peak_active = 0;
    int completed = 0;

    std::vector<acpp::net::awaitable<void>> tasks;
    tasks.push_back(TrackedTask(io_context, active, peak_active, completed, false));
    tasks.push_back(TrackedTask(io_context, active, peak_active, completed, true));
    tasks.push_back(TrackedTask(io_context, active, peak_active, completed, false));

    auto result = acpp::net::co_spawn(
        io_context,
        acpp::RunAwaitableBatch(
            io_context.get_executor(), std::move(tasks)),
        acpp::net::use_future);
    io_context.run();

    bool saw_failure = false;
    try {
        result.get();
    } catch (const std::runtime_error&) {
        saw_failure = true;
    }

    if (!saw_failure) return 1;
    if (peak_active != 3) return 2;
    if (active != 0 || completed != 3) return 3;
    return 0;
}
