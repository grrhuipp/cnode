#include <gtest/gtest.h>

#include "common/awaitable_batch.hpp"
#include "common/monitor_loop.hpp"

#include <asio/as_tuple.hpp>
#include <asio/post.hpp>
#include <asio/use_awaitable.hpp>

#include <stdexcept>
#include <vector>

namespace {

namespace net = ::net;
using ::common::MonitorLoop;


struct Lifetime {
    explicit Lifetime(bool& destroyed) : destroyed(destroyed) {}
    ~Lifetime() { destroyed = true; }
    bool& destroyed;
};

net::awaitable<void> FailLoop(int& starts) {
    ++starts;
    co_await net::post(net::use_awaitable);
    throw std::runtime_error("monitor loop failed");
}

net::awaitable<void> WaitLoop(net::steady_timer& gate, int& starts) {
    ++starts;
    (void)co_await gate.async_wait(net::as_tuple(net::use_awaitable));
}

struct Exit {
    std::string name;
    std::exception_ptr failure;
};

TEST(MonitorLoop, IndependentCompletionAndOwnership) {
    net::io_context io;
    net::steady_timer gate(io);
    gate.expires_at(net::steady_timer::time_point::max());
    bool context_destroyed = false;
    auto context = std::make_shared<Lifetime>(context_destroyed);
    int failing_starts = 0;
    int waiting_starts = 0;
    std::vector<Exit> exits;
    auto report = [&](std::string_view name, std::exception_ptr error) {
        exits.push_back({std::string(name), error});
    };
    auto failing = std::make_shared<common::MonitorLoop>(io.get_executor(), "failing",
        [&] { return FailLoop(failing_starts); }, report);
    auto waiting = std::make_shared<common::MonitorLoop>(io.get_executor(), "waiting",
        [context, &gate, &waiting_starts] { return WaitLoop(gate, waiting_starts); }, report);
    std::weak_ptr<common::MonitorLoop> waiting_owner = waiting;
    failing->Start();
    waiting->Start();
    waiting->Start();
    io.poll();
    const bool failure_reported_while_waiting =
        exits.size() == 1 && exits[0].name == "failing" && exits[0].failure;

    // Dropping the facade must not drop the factory context borrowed by its task.
    context.reset();
    waiting.reset();
    const bool context_retained = !context_destroyed && !waiting_owner.expired();
    failing->Start();
    if (auto active = waiting_owner.lock()) active->Start();
    io.poll();
    const bool only_failed_loop_restarted = failing_starts == 2 && waiting_starts == 1;
    gate.cancel();
    io.run();

    EXPECT_TRUE(failure_reported_while_waiting) << "a failed monitor must report without waiting for another loop's exit";
    EXPECT_TRUE(context_retained && context_destroyed && waiting_owner.expired()) << "the task must own its factory context until completion and then release it";
    EXPECT_TRUE(only_failed_loop_restarted) << "starting monitors again must not duplicate an active loop";
    EXPECT_TRUE(exits.size() == 3 && exits[1].failure && exits[2].name == "waiting" &&
                !exits[2].failure) << "each exit must retain its own name and failure status";
    ASSERT_FALSE(exits.empty());
    ASSERT_TRUE(exits[0].failure);
    bool original_type = false;
    try {
        std::rethrow_exception(exits[0].failure);
    } catch (const std::runtime_error&) {
        original_type = true;
    }
    EXPECT_TRUE(original_type) << "monitor completion must preserve the original error type";
}

TEST(MonitorLoop, FactoryFailureAllowsRestart) {
    net::io_context io;
    int reports = 0;
    auto loop = std::make_shared<common::MonitorLoop>(io.get_executor(), "factory",
        []() -> net::awaitable<void> { throw std::runtime_error("factory failed"); },
        [&](std::string_view name, std::exception_ptr failure) {
            if (name == "factory" && failure) ++reports;
        });
    loop->Start();
    io.run();
    io.restart();
    loop->Start();
    io.run();
    EXPECT_TRUE(reports == 2) << "factory failure must report and clear the active state";
}

TEST(MonitorLoop, WeakLoopSlotsPreserveOwnerUntilLastExit) {
    struct Owner {
        explicit Owner(bool& destroyed) : destroyed(destroyed) {}
        ~Owner() { destroyed = true; }
        bool& destroyed;
        std::weak_ptr<common::MonitorLoop> loops[2];
    };

    net::io_context io;
    net::steady_timer gate(io);
    gate.expires_at(net::steady_timer::time_point::max());
    bool destroyed = false;
    auto owner = std::make_shared<Owner>(destroyed);
    int starts[2] = {};
    std::vector<Exit> exits;
    for (size_t i = 0; i < 2; ++i) {
        auto loop = std::make_shared<common::MonitorLoop>(io.get_executor(), std::to_string(i),
            [owner, i, &gate, &starts] {
                return i == 0 ? FailLoop(starts[i]) : WaitLoop(gate, starts[i]);
            },
            [owner, &exits](std::string_view name, std::exception_ptr failure) {
                EXPECT_TRUE(!owner->destroyed) << "owner must survive its loop's exit callback";
                exits.push_back({std::string(name), failure});
            });
        owner->loops[i] = loop;
        loop->Start();
    }
    const auto failed_loop = owner->loops[0];
    const auto waiting_loop = owner->loops[1];
    // Both tasks have only been queued. Their factories must already retain the
    // owner, while its weak slots must allow reclamation after the final exit.
    owner.reset();
    const bool retained_before_execution = !destroyed;
    io.poll();
    const bool independent_exit = exits.size() == 1 && exits[0].name == "0" &&
        exits[0].failure && failed_loop.expired() && !waiting_loop.expired() && !destroyed;
    gate.cancel();
    io.run();

    EXPECT_TRUE(retained_before_execution && independent_exit) << "weak loop slots must preserve owner lifetime without joining unrelated loops";
    EXPECT_TRUE(destroyed && waiting_loop.expired() && exits.size() == 2 && !exits[1].failure) << "owner and loops must be reclaimed after the last exit without a reference cycle";
}

net::awaitable<void> CleanupLoop(net::steady_timer& work, net::steady_timer& cleanup,
                                int& starts, bool& cleaning, bool& cleaned) {
    ++starts;
    const auto [error] = co_await work.async_wait(net::as_tuple(net::use_awaitable));
    EXPECT_TRUE(error == net::error::operation_aborted) << "stop must cancel active work";
    co_await net::this_coro::reset_cancellation_state(net::disable_cancellation());
    cleaning = true;
    (void)co_await cleanup.async_wait(net::as_tuple(net::use_awaitable));
    cleaned = true;
}

TEST(MonitorLoop, StopJoinsActualCleanup) {
    net::io_context io;
    net::steady_timer work(io, net::steady_timer::time_point::max());
    net::steady_timer cleanup(io, net::steady_timer::time_point::max());
    int starts = 0;
    int reports = 0;
    bool cleaning = false;
    bool cleaned = false;
    bool joined = false;
    auto loop = std::make_shared<common::MonitorLoop>(io.get_executor(), "cleanup",
        [&] { return CleanupLoop(work, cleanup, starts, cleaning, cleaned); },
        [&](std::string_view, std::exception_ptr) { ++reports; });
    loop->Start();
    io.poll();
    EXPECT_TRUE(starts == 1 && !cleaning) << "loop must enter active work";
    loop->RequestStop();
    loop->RequestStop();
    loop->Start();
    net::cancellation_signal join_cancel;
    net::co_spawn(io, loop->AsyncJoin(),
        net::bind_cancellation_slot(join_cancel.slot(), [&](std::exception_ptr error) {
            EXPECT_TRUE(!error && cleaned) << "join must complete only after cleanup";
            joined = true;
        }));
    io.poll();
    join_cancel.emit(net::cancellation_type::all);
    io.poll();
    EXPECT_TRUE(cleaning && !cleaned && !joined && starts == 1) << "cancellation and repeated stop must not bypass actual cleanup";
    cleanup.cancel();
    io.run();
    EXPECT_TRUE(joined && reports == 0) << "intentional shutdown must not report a monitor failure";
    io.restart();
    loop->Start();
    net::co_spawn(io, loop->AsyncJoin(), [&](std::exception_ptr error) {
        EXPECT_TRUE(!error) << "joining an already completed loop must succeed";
    });
    io.run();
    EXPECT_TRUE(starts == 1) << "stopping is terminal and must reject restart";
}

TEST(MonitorLoop, StopBeforeExecutionPreventsWork) {
    net::io_context io;
    int starts = 0;
    int reports = 0;
    auto loop = std::make_shared<common::MonitorLoop>(io.get_executor(), "queued",
        [&] { return FailLoop(starts); },
        [&](std::string_view, std::exception_ptr) { ++reports; });
    loop->Start();
    loop->RequestStop();
    bool joined = false;
    net::co_spawn(io, loop->AsyncJoin(), [&](std::exception_ptr error) {
        EXPECT_TRUE(!error) << "queued stop must join successfully";
        joined = true;
    });
    io.run();
    EXPECT_TRUE(joined && starts == 0 && reports == 0) << "a stopped queued loop must not begin new work";
}

TEST(MonitorLoop, PartialStartFailureLeavesStartedLoopsJoinable) {
    struct FailingFactory {
        FailingFactory() = default;
        FailingFactory(const FailingFactory&) { throw std::bad_alloc(); }
        net::awaitable<void> operator()() const { co_return; }
    };
    net::io_context io;
    net::steady_timer work(io, net::steady_timer::time_point::max());
    int starts = 0;
    auto first = std::make_shared<common::MonitorLoop>(io.get_executor(), "first",
        [&] { return WaitLoop(work, starts); },
        [](std::string_view, std::exception_ptr) {});
    first->Start();
    io.poll();
    bool start_failed = false;
    try {
        const FailingFactory factory;
        auto second = std::make_shared<common::MonitorLoop>(
            io.get_executor(), "second", factory,
            [](std::string_view, std::exception_ptr) {});
        second->Start();
    } catch (const std::bad_alloc&) {
        start_failed = true;
    }
    first->RequestStop();
    bool joined = false;
    net::co_spawn(io, first->AsyncJoin(), [&](std::exception_ptr error) {
        EXPECT_TRUE(!error) << "partial start failure must leave earlier loops joinable";
        joined = true;
    });
    io.run();
    EXPECT_TRUE(start_failed && starts == 1 && joined) << "partial startup must retain a completion boundary for started loops";
}

TEST(MonitorLoop, StopJoinsEveryAcceptedBatchChild) {
    net::io_context io;
    net::steady_timer first(io, net::steady_timer::time_point::max());
    net::steady_timer second(io, net::steady_timer::time_point::max());
    int first_starts = 0;
    int second_starts = 0;
    int reports = 0;
    auto loop = std::make_shared<common::MonitorLoop>(io.get_executor(), "batch",
        [&] {
            std::vector<net::awaitable<void>> tasks;
            tasks.push_back(WaitLoop(first, first_starts));
            tasks.push_back(WaitLoop(second, second_starts));
            return ::common::RunAwaitableBatch(io.get_executor(), std::move(tasks));
        },
        [&](std::string_view, std::exception_ptr) { ++reports; });
    loop->Start();
    io.poll();
    EXPECT_TRUE(first_starts == 1 && second_starts == 1) << "batch must start both accepted tasks";
    loop->RequestStop();
    bool joined = false;
    net::co_spawn(io, loop->AsyncJoin(), [&](std::exception_ptr error) {
        EXPECT_TRUE(!error) << "stopped batch owner must join successfully";
        joined = true;
    });
    io.poll();
    EXPECT_TRUE(!joined) << "stop must not abandon an accepted batch";
    first.cancel();
    io.poll();
    EXPECT_TRUE(!joined) << "one completed child must not release the batch owner";
    second.cancel();
    io.run();
    EXPECT_TRUE(joined && reports == 0 && first_starts == 1 && second_starts == 1) << "join must cover every accepted child without starting another batch";
}

}  // namespace

