#include "acppnode/app/worker_mailbox.hpp"

#include <asio/as_tuple.hpp>
#include <asio/co_spawn.hpp>
#include <asio/executor_work_guard.hpp>
#include <asio/post.hpp>
#include <asio/steady_timer.hpp>
#include <asio/use_future.hpp>

#include <chrono>
#include <cstdio>
#include <exception>
#include <stdexcept>
#include <string>
#include <thread>

namespace {

void Require(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

acpp::net::awaitable<int> AddOne(int value) {
    co_return value + 1;
}

acpp::net::awaitable<void> WaitTimer(acpp::net::steady_timer& timer) {
    auto [ec] = co_await timer.async_wait(acpp::net::as_tuple(acpp::net::use_awaitable));
    (void)ec;
}

acpp::net::awaitable<void> FailTask() {
    throw std::runtime_error("posted task failed");
    co_return;
}

int Run() {
    acpp::net::io_context worker_io;
    auto work = acpp::net::make_work_guard(worker_io);
    std::thread worker_thread([&] { worker_io.run(); });

    acpp::WorkerMailbox mailbox(worker_io, 1);
    acpp::net::io_context caller_io;

    auto result = acpp::net::co_spawn(
        caller_io,
        mailbox.Post(AddOne(40)),
        acpp::net::use_future);
    caller_io.run();
    caller_io.restart();
    Require(result.get() == 41, "posted task did not return the worker result");
    Require(mailbox.Outstanding() == 0, "successful post must release its slot");

    acpp::net::steady_timer blocker(worker_io);
    blocker.expires_after(std::chrono::hours(1));
    auto held = mailbox.PostForFuture(WaitTimer(blocker));
    auto rejected = acpp::net::co_spawn(
        caller_io,
        mailbox.Post(AddOne(1)),
        acpp::net::use_future);
    caller_io.run();
    caller_io.restart();
    bool full = false;
    try {
        (void)rejected.get();
    } catch (const acpp::WorkerMailboxFull&) {
        full = true;
    }
    Require(full, "capacity 1 mailbox must reject a second in-flight post");
    Require(mailbox.Outstanding() == 1, "rejected post must not consume the held slot");
    acpp::net::post(worker_io, [&] { blocker.cancel(); });
    held.get();
    Require(mailbox.Outstanding() == 0, "held post must release its slot");

    auto after = acpp::net::co_spawn(
        caller_io,
        mailbox.Post(AddOne(2)),
        acpp::net::use_future);
    caller_io.run();
    caller_io.restart();
    Require(after.get() == 3, "mailbox must accept work after a slot is released");

    auto failed = acpp::net::co_spawn(
        caller_io,
        mailbox.Post(FailTask()),
        acpp::net::use_future);
    caller_io.run();
    caller_io.restart();
    bool failed_released = false;
    try {
        failed.get();
    } catch (const std::runtime_error& error) {
        failed_released = std::string(error.what()) == "posted task failed";
    }
    Require(failed_released, "posted exception must propagate to the caller");
    Require(mailbox.Outstanding() == 0, "failed post must still release its slot");

    acpp::net::steady_timer future_blocker(worker_io);
    future_blocker.expires_after(std::chrono::hours(1));
    auto future_held = mailbox.PostForFuture(WaitTimer(future_blocker));
    auto second_future = mailbox.PostForFuture(AddOne(8));
    bool future_full = false;
    try {
        (void)second_future.get();
    } catch (const acpp::WorkerMailboxFull&) {
        future_full = true;
    }
    Require(future_full, "PostForFuture must reject when the mailbox is full");
    acpp::net::post(worker_io, [&] { future_blocker.cancel(); });
    future_held.get();
    Require(mailbox.Outstanding() == 0, "PostForFuture must release its slot");

    work.reset();
    worker_thread.join();
    return 0;
}

}  // namespace

int main() {
    try {
        return Run();
    } catch (const std::exception& error) {
        std::fprintf(stderr, "worker_mailbox_test: %s\n", error.what());
        return 1;
    }
}
