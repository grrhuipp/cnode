#include <gtest/gtest.h>
#include "proxy/vless/vless_encryption.hpp"
#include "app/session_group_executor.hpp"
#include <asio/co_spawn.hpp>
#include <asio/executor_work_guard.hpp>
#include <asio/use_future.hpp>
#include <array>
#include <future>
#include <thread>

namespace {
using namespace ::vless;
using Ticket = std::array<uint8_t, 16>;
net::awaitable<bool> Seed(GroupCoordinator& coordinator,
                         std::shared_ptr<const VlessEncryptionConfig> config,
                         Ticket ticket, Ticket identity, bool expired = false) {
    VlessEncryptionIssuedTicket issued;
    issued.ticket = ticket;
    issued.pfs_key.bytes[0] = 73;
    issued.seconds = 60;
    issued.issued_at = std::chrono::steady_clock::now() -
        (expired ? std::chrono::seconds(61) : std::chrono::seconds(0));
    co_return co_await AuthenticateVlessTicket(coordinator, std::move(config), "ticket-in", issued, identity);
}

class VlessTicketService : public testing::Test {
protected:
    net::io_context io0, io1, control;
    net::executor_work_guard<net::io_context::executor_type> work0{io0.get_executor()};
    net::executor_work_guard<net::io_context::executor_type> work1{io1.get_executor()};
    net::executor_work_guard<net::io_context::executor_type> workc{control.get_executor()};
    std::shared_ptr<GroupCoordinator> coordinator;
    std::thread worker0, worker1, manager;
    std::shared_ptr<const VlessEncryptionConfig> config = std::make_shared<const VlessEncryptionConfig>();
    Ticket ticket{}, identity{};
    VlessEncryptionNfsKey nfs;

    void SetUp() override {
        identity[0] = 7;
        nfs.bytes[0] = 31;
        coordinator = std::make_shared<GroupCoordinator>(control, 1);
        coordinator->RegisterWorker(io0);
        coordinator->RegisterWorker(io1);
        worker0 = std::thread([this] { io0.run(); });
        worker1 = std::thread([this] { io1.run(); });
        manager = std::thread([this] { control.run(); });
    }
    void TearDown() override {
        auto stop = [](std::shared_ptr<GroupCoordinator> owner) -> net::awaitable<void> {
            owner->CloseAdmission();
            co_await owner->AsyncJoin();
            owner->ReleaseServices();
            co_await owner->Finalize();
        };
        try {
            net::co_spawn(control, stop(coordinator), net::use_future).get();
        } catch (const std::exception& error) {
            ADD_FAILURE() << "ticket coordinator teardown: " << error.what();
            io0.stop(); io1.stop(); control.stop();
        }
        coordinator.reset();
        work0.reset(); work1.reset(); workc.reset();
        worker0.join(); worker1.join(); manager.join();
    }
};

TEST_F(VlessTicketService, CrossWorkerResumePreservesAuthenticatedIdentityAndRejectsReplay) {
    ASSERT_TRUE(net::co_spawn(io0, Seed(*coordinator, config, ticket, identity), net::use_future).get());
    const auto resumed = net::co_spawn(io1,
        LookupVlessTicket(*coordinator, config, "ticket-in", ticket, nfs), net::use_future).get();
    ASSERT_TRUE(resumed);
    EXPECT_EQ(resumed->identity, identity);
    EXPECT_EQ(resumed->pfs_key.bytes[0], 73);
    EXPECT_FALSE(net::co_spawn(io1,
        LookupVlessTicket(*coordinator, config, "ticket-in", ticket, nfs), net::use_future).get());
    EXPECT_FALSE(net::co_spawn(io0,
        LookupVlessTicket(*coordinator, config, "ticket-in", ticket, nfs), net::use_future).get());
}

TEST_F(VlessTicketService, NamespaceMismatchDoesNotConsumeValidTicket) {
    ASSERT_TRUE(net::co_spawn(io0, Seed(*coordinator, config, ticket, identity), net::use_future).get());
    EXPECT_FALSE(net::co_spawn(io1,
        LookupVlessTicket(*coordinator, config, "other-in", ticket, nfs), net::use_future).get());
    const auto other = std::make_shared<const VlessEncryptionConfig>();
    EXPECT_FALSE(net::co_spawn(io1,
        LookupVlessTicket(*coordinator, other, "ticket-in", ticket, nfs), net::use_future).get());
    EXPECT_TRUE(net::co_spawn(io1,
        LookupVlessTicket(*coordinator, config, "ticket-in", ticket, nfs), net::use_future).get());
}

TEST_F(VlessTicketService, RejectsExpiredPublication) {
    EXPECT_FALSE(net::co_spawn(io1, Seed(*coordinator, config, ticket, identity, true), net::use_future).get());
}

TEST_F(VlessTicketService, FullMailboxRejectsWithoutWaitingForHeldCall) {
    std::promise<void> entered, release;
    auto entered_future = entered.get_future();
    auto released = release.get_future();
    auto holder = net::co_spawn(io1, coordinator->PostCall([&] {
        entered.set_value();
        released.wait();
        return true;
    }), net::use_future);
    // Always release the synchronous control-plane call before fixture teardown.
    struct Release {
        std::promise<void>& promise;
        ~Release() { if (active) promise.set_value(); }
        bool active = true;
    } guard{release};
    entered_future.get();
    auto overflow = net::co_spawn(io0,
        LookupVlessTicket(*coordinator, config, "ticket-in", ticket, nfs), net::use_future);
    EXPECT_THROW((void)overflow.get(), WorkerMailboxFull);
    release.set_value();
    guard.active = false;
    EXPECT_TRUE(holder.get());
}

TEST_F(VlessTicketService, ClosedAdmissionPropagatesCancellation) {
    coordinator->CloseAdmission();
    auto stopped = net::co_spawn(io1,
        LookupVlessTicket(*coordinator, config, "ticket-in", ticket, nfs), net::use_future);
    try {
        (void)stopped.get();
        FAIL() << "closed ticket service accepted lookup";
    } catch (const std::system_error& error) {
        EXPECT_EQ(error.code(), io_error::operation_aborted);
    }
}
}  // namespace
