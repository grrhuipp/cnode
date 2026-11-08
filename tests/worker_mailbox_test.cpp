#include <gtest/gtest.h>

#include "app/worker_mailbox.hpp"

#include <asio/as_tuple.hpp>
#include <asio/co_spawn.hpp>
#include <asio/executor_work_guard.hpp>
#include <asio/post.hpp>
#include <asio/steady_timer.hpp>
#include <asio/use_future.hpp>

#include <chrono>
#include <cstdio>
#include <exception>
#include <future>
#include <stdexcept>
#include <system_error>
#include <thread>
#include <type_traits>
#include <utility>

namespace {

void Require(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

::net::awaitable<int> AddOne(int value) {
    co_return value + 1;
}

::net::awaitable<void> WaitTimer(::net::steady_timer& timer) {
    auto [ec] = co_await timer.async_wait(::net::as_tuple(::net::use_awaitable));
    (void)ec;
}

::net::awaitable<void> FailTask() {
    throw std::runtime_error("posted task failed");
    co_return;
}

// Completes caller-side awaits; the posted bodies run on the worker thread.
template <typename T>
T Await(::net::io_context& caller_io, ::net::awaitable<T> awaitable) {
    auto future = ::net::co_spawn(caller_io, std::move(awaitable), ::net::use_future);
    caller_io.run();
    caller_io.restart();
    return future.get();
}

// Starts a caller-side await and returns once its admission has been decided.
template <typename T>
std::future<T> Start(::net::io_context& caller_io, ::net::awaitable<T> awaitable) {
    auto future = ::net::co_spawn(caller_io, std::move(awaitable), ::net::use_future);
    caller_io.poll();
    return future;
}

// Admission is decided before the first suspension, so rejection is observable
// without running the caller loop to completion (a held post may still be open).
template <typename Error, typename T>
bool RejectsAdmission(::net::io_context& caller_io, ::net::awaitable<T> awaitable) {
    auto future = Start(caller_io, std::move(awaitable));
    if (future.wait_for(std::chrono::seconds(0)) != std::future_status::ready) return false;
    try {
        (void)future.get();
    } catch (const Error& error) {
        if constexpr (std::is_same_v<Error, std::system_error>) {
            return error.code() == ::net::error::operation_aborted;
        }
        return true;
    }
    return false;
}

template <typename T>
bool ThrowsRuntimeError(::net::io_context& caller_io, ::net::awaitable<T> awaitable) {
    try {
        Await(caller_io, std::move(awaitable));
    } catch (const std::runtime_error&) {
        return true;
    }
    return false;
}

int Run() {
    ::net::io_context worker_io;
    auto work = ::net::make_work_guard(worker_io);
    std::thread worker_thread([&] { worker_io.run(); });

    ::WorkerMailbox mailbox(worker_io, 1);
    ::net::io_context caller_io;

    Require(Await(caller_io, mailbox.Post(AddOne(40))) == 41,
        "posted task did not return the worker result");
    Require(mailbox.Outstanding() == 0, "successful post must release its slot");

    const auto caller_thread = std::this_thread::get_id();
    const auto call_thread = Await(caller_io, mailbox.PostCall([] {
        return std::this_thread::get_id();
    }));
    Require(call_thread != caller_thread, "posted call must run on the owner thread");
    Require(mailbox.Outstanding() == 0, "successful call must release its slot");
    bool void_call_ran = false;
    Await(caller_io, mailbox.PostCall([&void_call_ran] { void_call_ran = true; }));
    Require(void_call_ran, "void posted call must run before completion");

    ::net::steady_timer blocker(worker_io);
    blocker.expires_after(std::chrono::hours(1));
    auto held = Start(caller_io, mailbox.Post(WaitTimer(blocker)));
    Require(mailbox.Outstanding() == 1, "accepted post must hold its slot");
    Require(RejectsAdmission<::WorkerMailboxFull>(caller_io, mailbox.Post(AddOne(1))),
        "capacity 1 mailbox must reject a second in-flight post");
    Require(RejectsAdmission<::WorkerMailboxFull>(caller_io, mailbox.PostCall([] { return 1; })),
        "capacity 1 mailbox must reject a call while a post is in flight");
    Require(mailbox.Outstanding() == 1, "rejected admissions must not consume the held slot");
    ::net::post(worker_io, [&] { blocker.cancel(); });
    caller_io.run();
    caller_io.restart();
    held.get();
    Require(mailbox.Outstanding() == 0, "held post must release its slot");

    Require(Await(caller_io, mailbox.Post(AddOne(2))) == 3,
        "mailbox must accept work after a slot is released");

    Require(ThrowsRuntimeError(caller_io, mailbox.Post(FailTask())),
        "posted exception must propagate to the caller");
    Require(mailbox.Outstanding() == 0, "failed post must still release its slot");
    Require(ThrowsRuntimeError(caller_io, mailbox.PostCall([]() -> int {
                throw std::runtime_error("posted call failed");
            })),
        "posted call exception must propagate to the caller");
    Require(mailbox.Outstanding() == 0, "failed call must still release its slot");

    // Closing must work even when every ordinary slot is occupied. Join is
    // not a posted task and must wait for the accepted coroutine to finish.
    ::net::steady_timer close_blocker(worker_io);
    close_blocker.expires_after(std::chrono::hours(1));
    auto close_held = Start(caller_io, mailbox.Post(WaitTimer(close_blocker)));
    mailbox.CloseAdmission();
    mailbox.CloseAdmission();
    Require(mailbox.IsClosed(), "admission closure must be permanent");
    auto joined = ::net::co_spawn(worker_io,
        mailbox.AsyncJoinAccepted(), ::net::use_future);
    Require(joined.wait_for(std::chrono::milliseconds(20)) == std::future_status::timeout,
        "join returned while accepted I/O was still pending");
    Require(RejectsAdmission<std::system_error>(caller_io, mailbox.Post(AddOne(10))),
        "closed awaitable admission must report cancellation, not full");
    Require(RejectsAdmission<std::system_error>(caller_io, mailbox.PostCall([] { return 10; })),
        "closed call admission must report cancellation, not full");
    ::net::post(worker_io, [&] { close_blocker.cancel(); });
    caller_io.run();
    caller_io.restart();
    close_held.get();
    Require(mailbox.Outstanding() == 0, "accepted post must release its slot after closure");
    joined.get();
    auto joined_again = ::net::co_spawn(worker_io,
        mailbox.AsyncJoinAccepted(), ::net::use_future);
    joined_again.get();

    work.reset();
    worker_thread.join();
    return 0;
}

}  // namespace

TEST(WorkerMailbox, Contract) {
    try {
        { ASSERT_EQ((::Run()), 0); return; }
    } catch (const std::exception& error) {
        std::fprintf(stderr, "worker_mailbox_test: %s\n", error.what());
        FAIL() << error.what();
    }
}
