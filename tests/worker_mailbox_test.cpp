#include <gtest/gtest.h>

#include "app/worker_mailbox.hpp"

#include <asio/as_tuple.hpp>
#include <asio/co_spawn.hpp>
#include <asio/executor_work_guard.hpp>
#include <asio/post.hpp>
#include <asio/steady_timer.hpp>
#include <asio/use_future.hpp>

#include <chrono>
#include <future>
#include <stdexcept>
#include <system_error>
#include <thread>
#include <utility>

namespace {
using namespace std::chrono_literals;

::net::awaitable<std::thread::id> PostedThread() {
    co_return std::this_thread::get_id();
}

::net::awaitable<void> WaitTimer(::net::steady_timer& timer) {
    (void)co_await timer.async_wait(::net::as_tuple(::net::use_awaitable));
}

::net::awaitable<void> FailTask() {
    throw std::runtime_error("posted task failed");
    co_return;
}

class WorkerMailboxTest : public ::testing::Test {
protected:
    WorkerMailboxTest()
        : work_(::net::make_work_guard(worker_io_)), mailbox_(worker_io_, 1),
          worker_thread_([this] { worker_io_.run(); }) {}

    ~WorkerMailboxTest() override {
        mailbox_.CloseAdmission();
        work_.reset();
        worker_io_.stop();
        worker_thread_.join();
    }

    void TearDown() override {
        mailbox_.CloseAdmission();
        auto joined = ::net::co_spawn(worker_io_, mailbox_.AsyncJoinAccepted(), ::net::use_future);
        joined.get();
        EXPECT_EQ(mailbox_.Outstanding(), 0u);
    }

    template <typename T>
    T Await(::net::awaitable<T> task) {
        auto future = ::net::co_spawn(caller_io_, std::move(task), ::net::use_future);
        caller_io_.run();
        caller_io_.restart();
        return future.get();
    }

    template <typename T>
    std::future<T> Start(::net::awaitable<T> task) {
        auto future = ::net::co_spawn(caller_io_, std::move(task), ::net::use_future);
        caller_io_.poll();
        return future;
    }

    ::net::io_context worker_io_;
    ::net::executor_work_guard<::net::io_context::executor_type> work_;
    ::WorkerMailbox mailbox_;
    ::net::io_context caller_io_;
    std::thread worker_thread_;
};

TEST_F(WorkerMailboxTest, PostedCoroutineRunsOnOwnerAndReleasesAdmissionSlot) {
    EXPECT_EQ(Await(mailbox_.Post(PostedThread())), worker_thread_.get_id());
    EXPECT_EQ(mailbox_.Outstanding(), 0u);
}

TEST_F(WorkerMailboxTest, PostedCallRunsOnOwnerAndReleasesAdmissionSlot) {
    const auto owner = Await(mailbox_.PostCall([] { return std::this_thread::get_id(); }));
    EXPECT_EQ(owner, worker_thread_.get_id());
    EXPECT_EQ(mailbox_.Outstanding(), 0u);
}

TEST_F(WorkerMailboxTest, VoidCallCompletesBeforeReturningToCaller) {
    bool ran = false;
    Await(mailbox_.PostCall([&ran] { ran = true; }));
    EXPECT_TRUE(ran);
    EXPECT_EQ(mailbox_.Outstanding(), 0u);
}

TEST_F(WorkerMailboxTest, FullMailboxRejectsBothAdmissionKindsAndReusesReleasedSlot) {
    ::net::steady_timer blocker(worker_io_);
    blocker.expires_after(1h);
    auto held = Start(mailbox_.Post(WaitTimer(blocker)));
    EXPECT_EQ(mailbox_.Outstanding(), 1u);
    auto post = Start(mailbox_.Post(PostedThread()));
    auto call = Start(mailbox_.PostCall([] { return std::this_thread::get_id(); }));
    EXPECT_EQ(post.wait_for(0s), std::future_status::ready);
    EXPECT_EQ(call.wait_for(0s), std::future_status::ready);
    EXPECT_EQ(mailbox_.Outstanding(), 1u);
    ::net::post(worker_io_, [&] { blocker.cancel(); });
    caller_io_.run();
    caller_io_.restart();
    held.get();
    EXPECT_THROW(post.get(), ::WorkerMailboxFull);
    EXPECT_THROW(call.get(), ::WorkerMailboxFull);
    EXPECT_EQ(mailbox_.Outstanding(), 0u);
    EXPECT_EQ(Await(mailbox_.Post(PostedThread())), worker_thread_.get_id());
}

TEST_F(WorkerMailboxTest, CoroutineFailurePropagatesAndReleasesAdmissionSlot) {
    EXPECT_THROW(Await(mailbox_.Post(FailTask())), std::runtime_error);
    EXPECT_EQ(mailbox_.Outstanding(), 0u);
    EXPECT_EQ(Await(mailbox_.Post(PostedThread())), worker_thread_.get_id());
}

TEST_F(WorkerMailboxTest, CallFailurePropagatesAndReleasesAdmissionSlot) {
    EXPECT_THROW(Await(mailbox_.PostCall([]() -> int {
        throw std::runtime_error("posted call failed");
    })), std::runtime_error);
    EXPECT_EQ(mailbox_.Outstanding(), 0u);
    EXPECT_EQ(Await(mailbox_.Post(PostedThread())), worker_thread_.get_id());
}

TEST_F(WorkerMailboxTest, CloseAtCapacityRejectsNewWorkAndJoinsAcceptedIo) {
    ::net::steady_timer blocker(worker_io_);
    blocker.expires_after(1h);
    auto held = Start(mailbox_.Post(WaitTimer(blocker)));
    mailbox_.CloseAdmission();
    mailbox_.CloseAdmission();
    EXPECT_TRUE(mailbox_.IsClosed());
    auto joined = ::net::co_spawn(worker_io_, mailbox_.AsyncJoinAccepted(), ::net::use_future);
    EXPECT_EQ(joined.wait_for(20ms), std::future_status::timeout);
    auto post = Start(mailbox_.Post(PostedThread()));
    auto call = Start(mailbox_.PostCall([] { return std::this_thread::get_id(); }));
    EXPECT_EQ(post.wait_for(0s), std::future_status::ready);
    EXPECT_EQ(call.wait_for(0s), std::future_status::ready);
    ::net::post(worker_io_, [&] { blocker.cancel(); });
    caller_io_.run();
    caller_io_.restart();
    held.get();
    EXPECT_EQ(mailbox_.Outstanding(), 0u);
    joined.get();
    for (auto* result : {&post, &call}) {
        try {
            (void)result->get();
            ADD_FAILURE() << "closed admission accepted new work";
        } catch (const std::system_error& error) {
            EXPECT_EQ(error.code(), ::net::error::operation_aborted);
        }
    }
    auto joined_again = ::net::co_spawn(worker_io_, mailbox_.AsyncJoinAccepted(), ::net::use_future);
    joined_again.get();
}
}  // namespace
