#include "common/monitor_loop.hpp"

#include <asio/as_tuple.hpp>
#include <asio/post.hpp>
#include <asio/use_awaitable.hpp>

#include <iostream>
#include <stdexcept>
#include <vector>

namespace {

namespace net = acpp::net;
using acpp::monitor_detail::MonitorLoop;

void Require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

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

void TestIndependentCompletionAndOwnership() {
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
    auto failing = std::make_shared<MonitorLoop>(io.get_executor(), "failing",
        [&] { return FailLoop(failing_starts); }, report);
    auto waiting = std::make_shared<MonitorLoop>(io.get_executor(), "waiting",
        [context, &gate, &waiting_starts] { return WaitLoop(gate, waiting_starts); }, report);
    std::weak_ptr<MonitorLoop> waiting_owner = waiting;
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

    Require(failure_reported_while_waiting,
            "a failed monitor must report without waiting for another loop's exit");
    Require(context_retained && context_destroyed && waiting_owner.expired(),
            "the task must own its factory context until completion and then release it");
    Require(only_failed_loop_restarted,
            "starting monitors again must not duplicate an active loop");
    Require(exits.size() == 3 && exits[1].failure && exits[2].name == "waiting" &&
                !exits[2].failure,
            "each exit must retain its own name and failure status");
    try {
        std::rethrow_exception(exits[0].failure);
    } catch (const std::runtime_error& error) {
        Require(std::string_view(error.what()) == "monitor loop failed",
                "monitor completion must preserve the original error");
    }
}

void TestFactoryFailure() {
    net::io_context io;
    int reports = 0;
    auto loop = std::make_shared<MonitorLoop>(io.get_executor(), "factory",
        []() -> net::awaitable<void> { throw std::runtime_error("factory failed"); },
        [&](std::string_view name, std::exception_ptr failure) {
            if (name == "factory" && failure) ++reports;
        });
    loop->Start();
    io.run();
    io.restart();
    loop->Start();
    io.run();
    Require(reports == 2, "factory failure must report and clear the active state");
}

void TestOwnerWithWeakLoopSlots() {
    struct Owner {
        explicit Owner(bool& destroyed) : destroyed(destroyed) {}
        ~Owner() { destroyed = true; }
        bool& destroyed;
        std::weak_ptr<MonitorLoop> loops[2];
    };

    net::io_context io;
    net::steady_timer gate(io);
    gate.expires_at(net::steady_timer::time_point::max());
    bool destroyed = false;
    auto owner = std::make_shared<Owner>(destroyed);
    int starts[2] = {};
    std::vector<Exit> exits;
    for (size_t i = 0; i < 2; ++i) {
        auto loop = std::make_shared<MonitorLoop>(io.get_executor(), std::to_string(i),
            [owner, i, &gate, &starts] {
                return i == 0 ? FailLoop(starts[i]) : WaitLoop(gate, starts[i]);
            },
            [owner, &exits](std::string_view name, std::exception_ptr failure) {
                Require(!owner->destroyed, "owner must survive its loop's exit callback");
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

    Require(retained_before_execution && independent_exit,
            "weak loop slots must preserve owner lifetime without joining unrelated loops");
    Require(destroyed && waiting_loop.expired() && exits.size() == 2 && !exits[1].failure,
            "owner and loops must be reclaimed after the last exit without a reference cycle");
}

}  // namespace

int main() {
    try {
        TestIndependentCompletionAndOwnership();
        TestFactoryFailure();
        TestOwnerWithWeakLoopSlots();
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
    return 0;
}
