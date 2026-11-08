#include <stdexcept>
#include <gtest/gtest.h>

#include "vless_ticket_service.hpp"
#include "app/session_group_executor.hpp"
#include <asio/co_spawn.hpp>
#include <asio/executor_work_guard.hpp>
#include <asio/post.hpp>
#include <asio/redirect_error.hpp>
#include <asio/steady_timer.hpp>
#include <asio/use_future.hpp>
#include <array>
#include <atomic>
#include <cstdlib>
#include <future>
#include <iostream>
#include <thread>

namespace {
using namespace ::vless;
using Ticket = std::array<uint8_t, 16>;
void Check(bool value, const char* what) {
    if (!value) { std::cerr << what << '\n'; ADD_FAILURE() << "contract assertion failed; see diagnostic above"; throw std::runtime_error("contract assertion failed"); }
}
struct Hooks final : ExecutionDomain::Hooks {
    explicit Hooks(std::atomic<int>& alive) : alive_(alive) { ++alive_; }
    ~Hooks() override { --alive_; }
    void Enter() noexcept override {}
    void Leave() noexcept override {}
    void OnFailure(std::exception_ptr) noexcept override { std::terminate(); }
    std::atomic<int>& alive_;
};
net::awaitable<bool> Seed(std::shared_ptr<const VlessEncryptionConfig> config,
                          Ticket ticket, Ticket identity, bool expired = false) {
    VlessEncryptionIssuedTicket issued;
    issued.ticket = ticket;
    issued.pfs_key.bytes[0] = 73;
    issued.seconds = 60;
    issued.issued_at = std::chrono::steady_clock::now() -
        (expired ? std::chrono::seconds(61) : std::chrono::seconds(0));
    co_return co_await AuthenticateVlessTicket(std::move(config), "ticket-in", issued, identity);
}
net::awaitable<bool> HoldSlot(net::steady_timer& gate, std::promise<void>& entered) {
    entered.set_value();
    IoErrorCode error;
    co_await gate.async_wait(net::redirect_error(net::use_awaitable, error));
    co_return error == io_error::operation_aborted;
}
net::awaitable<void> StopCoordinator(std::shared_ptr<GroupCoordinator> coordinator) {
    co_await coordinator->AsyncJoin();
    coordinator->ReleaseServices();
}
}
TEST(VlessTicketService, Contract) {
    net::io_context io0, io1, control;
    auto work0 = net::make_work_guard(io0);
    auto work1 = net::make_work_guard(io1);
    auto workc = net::make_work_guard(control);
    auto coordinator = std::make_shared<GroupCoordinator>(control, 1);
    coordinator->RegisterWorker(0, io0, io0.get_executor());
    coordinator->RegisterWorker(1, io1, io1.get_executor());
    std::atomic<int> physical_hosts{0};
    auto domain0 = ExecutionDomain::Create(io0, 0, io0.get_executor(),
        std::make_shared<Hooks>(physical_hosts), coordinator);
    auto domain1 = ExecutionDomain::Create(io1, 1, io1.get_executor(),
        std::make_shared<Hooks>(physical_hosts), coordinator);
    std::thread worker0([&] { io0.run(); });
    std::thread worker1([&] { io1.run(); });
    std::thread manager([&] { control.run(); });
    auto config = std::make_shared<const VlessEncryptionConfig>();
    auto other_config = std::make_shared<const VlessEncryptionConfig>();
    Ticket ticket{}, identity{};
    identity[0] = 7;
    auto seed = net::co_spawn(domain0->Executor(), Seed(config, ticket, identity), net::use_future);
    Check(seed.get(), "ticket publication failed");
    // A directory lease must not retain the originating physical host.
    domain0.reset();
    std::promise<void> drained;
    auto drained_future = drained.get_future();
    net::post(control, [&] { net::post(io0, [&] { drained.set_value(); }); });
    drained_future.get();
    Check(physical_hosts.load() == 1, "ticket retained physical connection capabilities");
    VlessEncryptionNfsKey nfs;
    nfs.bytes[0] = 31;
    auto wrong_tag = net::co_spawn(domain1->Executor(),
        LookupVlessTicket(config, "other-in", ticket, nfs), net::use_future);
    Check(!wrong_tag.get(), "cross-inbound directory lookup accepted");
    auto wrong_namespace = net::co_spawn(domain1->Executor(),
        LookupVlessTicket(other_config, "ticket-in", ticket, nfs), net::use_future);
    Check(!wrong_namespace.get(), "cross-configuration directory lookup accepted");
    auto remote = net::co_spawn(domain1->Executor(),
        LookupVlessTicket(config, "ticket-in", ticket, nfs), net::use_future);
    auto resumed = remote.get();
    Check(resumed && resumed->identity == identity && resumed->pfs_key.bytes[0] == 73,
          "cross-Worker authentication values changed");
    auto replay = net::co_spawn(domain1->Executor(),
        LookupVlessTicket(config, "ticket-in", ticket, nfs), net::use_future);
    Check(!replay.get(), "cross-Worker replay accepted");
    auto same_worker = ExecutionDomain::Create(io0, 0, io0.get_executor(),
        std::make_shared<Hooks>(physical_hosts), coordinator);
    auto local_replay = net::co_spawn(same_worker->Executor(),
        LookupVlessTicket(config, "ticket-in", ticket, nfs), net::use_future);
    Check(!local_replay.get(), "same-Worker replay accepted");
    ticket[0] = 1;
    auto expired = net::co_spawn(domain1->Executor(), Seed(config, ticket, identity, true), net::use_future);
    Check(!expired.get(), "expired ticket published");
    net::steady_timer gate(control);
    gate.expires_at(std::chrono::steady_clock::time_point::max());
    std::promise<void> entered;
    auto entered_future = entered.get_future();
    auto holder = net::co_spawn(domain1->Executor(),
        coordinator->Post(HoldSlot(gate, entered)), net::use_future);
    entered_future.get();
    auto overflow = net::co_spawn(same_worker->Executor(),
        LookupVlessTicket(config, "ticket-in", ticket, nfs), net::use_future);
    bool full = false;
    try { (void)overflow.get(); } catch (const WorkerMailboxFull&) { full = true; }
    Check(full, "full authentication mailbox did not reject immediately");
    net::post(control, [&] { gate.cancel(); });
    Check(holder.get(), "held mailbox operation failed to join");
    coordinator->CloseAdmission();
    auto stopped = net::co_spawn(domain1->Executor(),
        LookupVlessTicket(config, "ticket-in", ticket, nfs), net::use_future);
    bool closed = false;
    try { (void)stopped.get(); } catch (const std::system_error& error) {
        closed = error.code() == io_error::operation_aborted;
    }
    Check(closed, "stopped ticket owner coordinator accepted a request");
    auto joined = net::co_spawn(control, StopCoordinator(coordinator), net::use_future);
    joined.get();
    domain1.reset();
    same_worker.reset();
    auto finalized = net::co_spawn(control, coordinator->Finalize(), net::use_future);
    finalized.get();
    coordinator.reset();
    work0.reset(); work1.reset(); workc.reset();
    worker0.join(); worker1.join(); manager.join();
    Check(physical_hosts.load() == 0, "physical hosts survived joined shutdown");
}
