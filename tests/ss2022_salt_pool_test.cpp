#include <gtest/gtest.h>

#include "app/group_coordinator.hpp"
#include "proxy/shadowsocks/ss_salt_pool.hpp"
#include <asio/bind_cancellation_slot.hpp>
#include <asio/cancellation_signal.hpp>
#include <asio/co_spawn.hpp>
#include <asio/executor_work_guard.hpp>
#include <asio/post.hpp>
#include <asio/use_future.hpp>

#include <array>
#include <chrono>
#include <future>
#include <thread>

namespace {
using Admission = proxy::Ss2022SaltAdmission;
using Clock = proxy::Ss2022SaltPool::Clock;

proxy::KeyBytes Salt(uint8_t byte, uint8_t size = 16) {
    proxy::KeyBytes salt;
    salt.size = size;
    salt.bytes.fill(byte);
    return salt;
}

TEST(Ss2022SaltPool, KeysContainFullSaltAndLength) {
    proxy::Ss2022SaltPool pool;
    const auto now = Clock::time_point{};
    auto short_salt = Salt(7);
    auto long_salt = Salt(7, 32);
    EXPECT_EQ(pool.Admit(short_salt.span(), now), Admission::Accepted);
    EXPECT_EQ(pool.Admit(long_salt.span(), now), Admission::Accepted);
    EXPECT_EQ(pool.Admit(short_salt.span(), now), Admission::Replayed);
    EXPECT_EQ(pool.Admit(long_salt.span(), now), Admission::Replayed);
    long_salt.bytes.back() ^= 1;
    EXPECT_EQ(pool.Admit(long_salt.span(), now), Admission::Accepted);
    EXPECT_EQ(pool.Size(), 3u);
}

TEST(Ss2022SaltPool, RetainsUntilExactSixtyFiveSecondBoundaryWithoutRefreshingReplay) {
    proxy::Ss2022SaltPool pool;
    const auto now = Clock::time_point{};
    const auto salt = Salt(1);
    EXPECT_EQ(pool.Admit(salt.span(), now), Admission::Accepted);
    EXPECT_EQ(pool.Admit(salt.span(), now + proxy::Ss2022SaltPool::kRetention -
        std::chrono::nanoseconds(1)), Admission::Replayed);
    EXPECT_EQ(pool.Admit(salt.span(), now + proxy::Ss2022SaltPool::kRetention), Admission::Accepted);
    EXPECT_EQ(pool.Size(), 1u);
}

TEST(Ss2022SaltPool, FullTableRejectsNewSaltWithoutEvictingUnexpiredEntries) {
    proxy::Ss2022SaltPool pool(2);
    const auto now = Clock::time_point{};
    const auto first = Salt(1), second = Salt(2, 32), third = Salt(3);
    EXPECT_EQ(pool.Admit(first.span(), now), Admission::Accepted);
    EXPECT_EQ(pool.Admit(second.span(), now + std::chrono::seconds(1)), Admission::Accepted);
    EXPECT_EQ(pool.Admit(third.span(), now + std::chrono::seconds(2)), Admission::Limited);
    EXPECT_EQ(pool.Admit(first.span(), now + std::chrono::seconds(2)), Admission::Replayed);
    EXPECT_EQ(pool.Admit(second.span(), now + std::chrono::seconds(2)), Admission::Replayed);
    EXPECT_EQ(pool.Size(), 2u);
    EXPECT_EQ(pool.Admit(third.span(), now + proxy::Ss2022SaltPool::kRetention), Admission::Accepted);
    EXPECT_EQ(pool.Admit(second.span(), now + proxy::Ss2022SaltPool::kRetention), Admission::Replayed);
    EXPECT_EQ(pool.Size(), 2u);
}

TEST(Ss2022SaltPool, InvalidLengthsAndZeroCapacityFailClosed) {
    proxy::Ss2022SaltPool pool;
    const std::array<uint8_t, 33> bytes{};
    for (const auto size : {0u, 15u, 17u, 31u, 33u}) {
        EXPECT_EQ(pool.Admit(std::span(bytes).first(size), Clock::time_point{}), Admission::Limited);
    }
    EXPECT_EQ(pool.Size(), 0u);
    proxy::Ss2022SaltPool empty(0);
    EXPECT_EQ(empty.Admit(Salt(1).span(), Clock::time_point{}), Admission::Limited);
}

TEST(Ss2022SaltPool, AllocationFailureRejectsWithoutForgettingAcceptedSalt) {
    proxy::Ss2022SaltPool pool(4);
    const auto first = Salt(1), second = Salt(2);
    const auto now = Clock::time_point{};
    ASSERT_EQ(pool.Admit(first.span(), now), Admission::Accepted);
    const auto failures = common::rejected_process_allocations;
    common::reject_next_process_allocation = true;
    const auto result = pool.Admit(second.span(), now);
    common::reject_next_process_allocation = false;
    EXPECT_EQ(result, Admission::Limited);
    EXPECT_EQ(common::rejected_process_allocations, failures + 1);
    EXPECT_EQ(pool.Size(), 1u);
    EXPECT_EQ(pool.Admit(first.span(), now), Admission::Replayed);
    EXPECT_EQ(pool.Admit(second.span(), now), Admission::Accepted);
}

class SaltCoordinator : public testing::Test {
protected:
    net::io_context control, first, second;
    net::executor_work_guard<net::io_context::executor_type> control_work{control.get_executor()};
    net::executor_work_guard<net::io_context::executor_type> first_work{first.get_executor()};
    net::executor_work_guard<net::io_context::executor_type> second_work{second.get_executor()};
    std::shared_ptr<app::GroupCoordinator> coordinator;
    std::thread control_thread, first_thread, second_thread;

    void Start(size_t capacity) {
        coordinator = std::make_shared<app::GroupCoordinator>(control, capacity);
        coordinator->RegisterWorker();
        coordinator->RegisterWorker();
        control_thread = std::thread([this] { control.run(); });
        first_thread = std::thread([this] { first.run(); });
        second_thread = std::thread([this] { second.run(); });
    }
    Admission Admit(net::io_context& worker, const proxy::KeyBytes& salt) {
        return net::co_spawn(worker, proxy::AdmitSs2022RequestSalt(*coordinator, salt), net::use_future).get();
    }
    void TearDown() override {
        if (coordinator) {
            coordinator->CloseAdmission();
            net::co_spawn(control, [this]() -> net::awaitable<void> {
                co_await coordinator->AsyncJoin();
                coordinator->ReleaseServices();
                co_await coordinator->Finalize();
            }, net::use_future).get();
            coordinator.reset();
        }
        control_work.reset(); first_work.reset(); second_work.reset();
        if (control_thread.joinable()) control_thread.join();
        if (first_thread.joinable()) first_thread.join();
        if (second_thread.joinable()) second_thread.join();
    }
};

TEST_F(SaltCoordinator, TwoExplicitWorkerReactorsShareOneAuthoritativePool) {
    Start(2);
    const auto salt = Salt(9, 32);
    EXPECT_EQ(Admit(first, salt), Admission::Accepted);
    EXPECT_EQ(Admit(second, salt), Admission::Replayed);
    EXPECT_EQ(Admit(first, salt), Admission::Replayed);
    EXPECT_EQ(Admit(second, Salt(10)), Admission::Accepted);
}

TEST_F(SaltCoordinator, MailboxCapacityAndClosedAdmissionFailClosedAndJoin) {
    Start(1);
    const auto salt = Salt(4);
    std::promise<void> entered, release;
    auto released = release.get_future().share();
    auto held = net::co_spawn(first, coordinator->PostCall([&entered, released] {
        entered.set_value();
        released.wait();
    }), net::use_future);
    entered.get_future().get();
    const auto limited = Admit(second, salt);
    release.set_value();
    held.get();
    EXPECT_EQ(limited, Admission::Limited);
    EXPECT_EQ(Admit(second, salt), Admission::Accepted);
    coordinator->CloseAdmission();
    try {
        (void)Admit(first, Salt(5));
        ADD_FAILURE() << "closed salt admission succeeded";
    } catch (const IoSystemError& error) {
        EXPECT_EQ(error.code(), net::error::operation_aborted);
    }
}

TEST_F(SaltCoordinator, CancellationJoinsAcceptedOwnerWorkBeforeReturning) {
    Start(2);
    const auto salt = Salt(11);
    std::promise<void> entered, release, submitted;
    auto released = release.get_future().share();
    auto held = net::co_spawn(first, coordinator->PostCall([&entered, released] {
        entered.set_value();
        released.wait();
    }), net::use_future);
    entered.get_future().get();
    net::cancellation_signal cancellation;
    auto admitted = net::co_spawn(second, proxy::AdmitSs2022RequestSalt(*coordinator, salt),
        net::bind_cancellation_slot(cancellation.slot(), net::use_future));
    net::post(second, [&] {
        cancellation.emit(net::cancellation_type::all);
        submitted.set_value();
    });
    submitted.get_future().get();
    release.set_value();
    held.get();
    EXPECT_EQ(admitted.get(), Admission::Accepted);
    EXPECT_EQ(Admit(first, salt), Admission::Replayed);
}

}  // namespace
