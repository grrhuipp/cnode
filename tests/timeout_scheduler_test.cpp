#include "acppnode/transport/internet/timeout_scheduler.hpp"
#include "acppnode/transport/internet/async_delay.hpp"

#include <asio/co_spawn.hpp>
#include <asio/executor_work_guard.hpp>
#include <asio/post.hpp>
#include <asio/strand.hpp>
#include <asio/use_future.hpp>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <future>
#include <memory>
#include <thread>
#include <type_traits>
#include <vector>

namespace {
using namespace std::chrono_literals;
static_assert(noexcept(std::declval<acpp::TimeoutScheduler&>().Cancel(
    std::declval<acpp::TimeoutToken&>())));
static_assert(std::is_nothrow_move_assignable_v<acpp::TimeoutToken>);

class SchedulerScope final {
public:
    explicit SchedulerScope(acpp::net::any_io_executor executor)
        : executor_(std::move(executor)) {
        acpp::TimeoutScheduler::Install(executor_);
    }
    ~SchedulerScope() {
        acpp::TimeoutScheduler::ReleaseForExecutor(executor_);
    }
private:
    acpp::net::any_io_executor executor_;
};

bool TestDeadlineCancellationAndOwner() {
    acpp::net::io_context io;
    SchedulerScope scheduler_scope(io.get_executor());
    auto owner = acpp::net::make_strand(io);
    auto& scheduler = acpp::TimeoutScheduler::ForExecutor(owner);
    bool first_ran = false;
    bool cancelled_ran = false;
    bool after_throw_ran = false;
    bool owner_correct = true;
    acpp::TimeoutToken cancelled;
    auto first = scheduler.ScheduleAfter(0ms, owner, [&] {
        owner_correct = owner_correct && owner.running_in_this_thread();
        first_ran = true;
        scheduler.Cancel(cancelled);
    });
    cancelled = scheduler.ScheduleAfter(0ms, owner, [&] { cancelled_ran = true; });
    auto throwing = scheduler.ScheduleAfter(0ms, owner, [] { throw 1; });
    auto survivor = scheduler.ScheduleAfter(2ms, owner, [&] {
        owner_correct = owner_correct && owner.running_in_this_thread();
        after_throw_ran = true;
    });
    std::vector<std::thread> threads;
    for (unsigned i = 0; i < 4; ++i) threads.emplace_back([&] { io.run(); });
    for (auto& thread : threads) thread.join();
    return first_ran && !cancelled_ran && after_throw_ran && owner_correct && !first.Valid();
}

bool TestDestructionMoveAndWrongOwner() {
    acpp::net::io_context io;
    acpp::net::io_context other;
    SchedulerScope scheduler_scope(io.get_executor());
    SchedulerScope other_scheduler_scope(other.get_executor());
    auto owner = acpp::net::make_strand(io);
    auto& scheduler = acpp::TimeoutScheduler::ForExecutor(owner);
    auto& wrong = acpp::TimeoutScheduler::ForExecutor(other.get_executor());
    bool abandoned_ran = false;
    bool replaced_ran = false;
    bool survivor_ran = false;
    { auto abandoned = scheduler.ScheduleAfter(0ms, owner, [&] { abandoned_ran = true; }); }
    auto replaced = scheduler.ScheduleAfter(0ms, owner, [&] { replaced_ran = true; });
    auto survivor = scheduler.ScheduleAfter(1ms, owner, [&] { survivor_ran = true; });
    wrong.Cancel(survivor);
    if (!survivor.Valid()) return false;
    replaced = std::move(survivor);
    io.run();
    return !abandoned_ran && !replaced_ran && survivor_ran;
}

bool TestCapacityAndReclamation() {
    acpp::net::io_context io;
    SchedulerScope scheduler_scope(io.get_executor());
    auto owner = acpp::net::make_strand(io);
    auto& scheduler = acpp::TimeoutScheduler::ForExecutor(owner);
    std::vector<acpp::TimeoutToken> tokens;
    tokens.reserve(acpp::TimeoutScheduler::kCapacity);
    for (std::size_t i = 0; i < acpp::TimeoutScheduler::kCapacity; ++i)
        tokens.push_back(scheduler.ScheduleAfter(1h, owner, [] {}));
    bool rejected = false;
    try { auto extra = scheduler.ScheduleAfter(1h, owner, [] {}); }
    catch (const std::length_error&) { rejected = true; }
    tokens.clear();
    io.run();
    io.restart();
    bool recovered = false;
    auto replacement = scheduler.ScheduleAfter(0ms, owner, [&] { recovered = true; });
    io.run();
    return rejected && recovered;
}

bool TestManySessionsAndLifetime() {
    acpp::net::io_context io;
    SchedulerScope scheduler_scope(io.get_executor());
    auto& scheduler = acpp::TimeoutScheduler::ForExecutor(io.get_executor());
    std::atomic<unsigned> completed{0};
    std::vector<std::future<void>> joins;
    constexpr unsigned count = 64;
    for (unsigned i = 0; i < count; ++i) {
        auto owner = acpp::net::make_strand(io);
        joins.push_back(acpp::net::co_spawn(owner, [&, owner]() -> acpp::net::awaitable<void> {
            auto state = std::make_unique<bool>(false);
            auto token = scheduler.ScheduleAfter(1ms, owner, [raw = state.get(), owner] {
                if (!owner.running_in_this_thread()) throw 1;
                *raw = true;
            });
            acpp::AsyncDelay delay(owner);
            co_await delay.WaitFor(5ms);
            if (!*state) throw 2;
            auto doomed = scheduler.ScheduleAfter(0ms, owner, [raw = state.get()] { *raw = false; });
            scheduler.Cancel(doomed);
            state.reset();
            ++completed;
        }, acpp::net::use_future));
    }
    std::vector<std::thread> threads;
    for (unsigned i = 0; i < 4; ++i) threads.emplace_back([&] { io.run(); });
    for (auto& thread : threads) thread.join();
    for (auto& join : joins) join.get();
    return completed == count;
}
}

int main() {
    try {
        const bool deadline = TestDeadlineCancellationAndOwner();
        const bool lifetime = TestDestructionMoveAndWrongOwner();
        const bool capacity = TestCapacityAndReclamation();
        const bool parallel = TestManySessionsAndLifetime();
        std::printf("timeout scheduler: deadline=%d lifetime=%d capacity=%d parallel=%d\n",
            deadline, lifetime, capacity, parallel);
        return deadline && lifetime && capacity && parallel ? 0 : 1;
    } catch (const std::exception& error) {
        std::fprintf(stderr, "timeout scheduler: %s\n", error.what());
        return 1;
    } catch (...) { return 1; }
}
