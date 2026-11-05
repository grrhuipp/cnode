#include "acppnode/app/session_group_executor.hpp"

#include <asio/co_spawn.hpp>
#include <asio/bind_cancellation_slot.hpp>
#include <asio/cancellation_signal.hpp>
#include <asio/redirect_error.hpp>
#include <asio/steady_timer.hpp>
#include <asio/use_future.hpp>
#include <atomic>
#include <cstdlib>
#include <future>
#include <iostream>
#include <thread>
#include <vector>

namespace {
using namespace acpp;
void Require(bool condition, const char* message) {
    if (!condition) {
        std::cerr << message << '\n';
        std::abort();
    }
}

struct Hooks final : ExecutionDomain::Hooks {
    explicit Hooks(std::atomic<unsigned>& live) : live(live) { ++live; }
    ~Hooks() override { --live; }
    void Enter() noexcept override {
        Require(!entered.exchange(true), "domain acquired by concurrent owners");
    }
    void Leave() noexcept override {
        Require(entered.exchange(false), "domain released without an owner");
    }
    void OnFailure(std::exception_ptr) noexcept override { std::terminate(); }
    std::atomic<unsigned>& live;
    std::atomic<bool> entered{false};
};

net::awaitable<void> Join(std::shared_ptr<ExecutionDomain> from,
                           std::shared_ptr<ExecutionDomain> to) {
    co_await from->Join(std::move(to));
}
net::awaitable<std::thread::id> ThreadId() { co_return std::this_thread::get_id(); }
net::awaitable<std::thread::id> PendingReadiness(
    net::steady_timer& timer, std::promise<void>& armed) {
    armed.set_value();
    IoErrorCode error;
    co_await timer.async_wait(net::redirect_error(net::use_awaitable, error));
    Require(error == net::error::operation_aborted, "migrated readiness was not cancelled");
    co_return std::this_thread::get_id();
}

net::awaitable<void> Hold(net::steady_timer& timer, std::promise<void>& armed) {
    armed.set_value();
    IoErrorCode error;
    co_await timer.async_wait(net::redirect_error(net::use_awaitable, error));
}

void StableDomainOwnership() {
    net::io_context first, second, third;
    auto first_work = net::make_work_guard(first);
    auto second_work = net::make_work_guard(second);
    auto third_work = net::make_work_guard(third);
    auto coordinator = std::make_shared<GroupCoordinator>(first, 2);
    std::atomic<unsigned> live{0};
    auto make = [&](net::io_context& io, uint32_t id) {
        return ExecutionDomain::Create(io, id, io.get_executor(),
            std::make_shared<Hooks>(live), coordinator);
    };
    auto a = make(first, 0);
    auto b = make(second, 1);
    auto c = make(third, 2);
    auto independent = make(first, 0);
    std::thread t0([&] { first.run(); });
    std::thread t1([&] { second.run(); });
    std::thread t2([&] { third.run(); });

    const auto initial = net::co_spawn(a->Executor(), ThreadId(), net::use_future).get();
    const auto target = net::co_spawn(b->Executor(), ThreadId(), net::use_future).get();
    Require(initial != target, "fixture did not start on independent workers");
    net::steady_timer pending(first, net::steady_timer::time_point::max());
    std::promise<void> armed;
    auto readiness = net::co_spawn(a->Executor(), PendingReadiness(pending, armed), net::use_future);
    armed.get_future().get();
    net::co_spawn(b->Executor(), Join(b, a), net::use_future).get();
    Require(a->SharesGroup(*b), "joined domains do not share a group");
    Require(a->OwnerId() == 1, "join did not transfer execution ownership");
    // This timer was registered before migration on the original reactor. Its
    // completion must execute on the new owner, without moving the timer/frame.
    net::co_spawn(a->Executor(), [&pending]() -> net::awaitable<void> {
        pending.cancel();
        co_return;
    }, net::use_future).get();
    Require(readiness.get() == target, "old reactor resumed on the wrong owner");
    Require(net::co_spawn(independent->Executor(), ThreadId(), net::use_future).get() == initial,
            "migration moved an unrelated domain");
    Require(!a->SharesGroup(*independent), "migration merged an unrelated domain");

    // Overlapping unions serialize rather than deadlocking or running a domain
    // simultaneously under two owners.
    auto forward = net::co_spawn(c->Executor(), Join(c, a), net::use_future);
    auto reverse = net::co_spawn(a->Executor(), Join(a, c), net::use_future);
    forward.get();
    reverse.get();
    Require(a->SharesGroup(*c), "overlapping joins did not converge");
    Require(net::co_spawn(c->Executor(), ThreadId(), net::use_future).get() == target,
            "overlapping joins lost the existing group owner");

    std::promise<void> delivered;
    unsigned count = 0;
    std::vector<std::thread> producers;
    for (unsigned producer = 0; producer != 4; ++producer) {
        producers.emplace_back([&] {
            for (unsigned item = 0; item != 500; ++item) {
                a->Execute([&] {
                    Require(std::this_thread::get_id() == target,
                            "cross-thread submission ran on the wrong owner");
                    if (++count == 2000) delivered.set_value();
                });
            }
        });
    }
    for (auto& producer : producers) producer.join();
    delivered.get_future().get();

    net::cancellation_signal cancel_merge;
    auto cancelled_merge = net::co_spawn(a->Executor(), Join(a, independent),
        net::bind_cancellation_slot(cancel_merge.slot(), net::use_future));
    a->Execute([&] { cancel_merge.emit(net::cancellation_type::all); });
    try { cancelled_merge.get(); }
    catch (const std::system_error& error) {
        Require(error.code() == net::error::operation_aborted, "unexpected merge cancellation error");
    }
    // Cancellation may win admission or race an irrevocable admitted union;
    // neither outcome may strand either execution token.
    net::co_spawn(a->Executor(), [&cancel_merge]() -> net::awaitable<void> {
        // Asio's completed co_spawn cancellation handler retains its executor
        // until the source slot is cleared. Retire that fixture-owned root on
        // the same owner as emit(), before joining domain shutdown.
        cancel_merge.slot().clear();
        co_return;
    }, net::use_future).get();
    net::co_spawn(independent->Executor(), ThreadId(), net::use_future).get();

    // Capacity bounds admission, not already admitted completion/retirement.
    net::steady_timer hold(first, net::steady_timer::time_point::max());
    net::steady_timer hold_second(first, net::steady_timer::time_point::max());
    std::promise<void> holding, holding_second;
    auto held = net::co_spawn(first, coordinator->Post(Hold(hold, holding)), net::use_future);
    auto held_second = net::co_spawn(first,
        coordinator->Post(Hold(hold_second, holding_second)), net::use_future);
    holding.get_future().get();
    holding_second.get_future().get();
    bool full = false;
    try { net::co_spawn(b->Executor(), Join(b, a), net::use_future).get(); }
    catch (const WorkerMailboxFull&) { full = true; }
    Require(full, "full coordinator admitted another merge");
    net::post(first, [&] { hold.cancel(); hold_second.cancel(); });
    held.get();
    held_second.get();

    // A long session must not retain thousands of completed upload hosts.
    for (unsigned i = 0; i != 2000; ++i) {
        auto upload = make((i & 1) ? second : first, (i & 1) ? 1 : 0);
        net::co_spawn(upload->Executor(), Join(upload, a), net::use_future).get();
        upload.reset();
    }
    net::co_spawn(a->Executor(), []() -> net::awaitable<void> { co_return; }, net::use_future).get();
    coordinator->CloseAdmission();
    struct Returned final : GroupCoordinator::ReservedOperation {
        std::promise<void>& complete;
        explicit Returned(std::promise<void>& value) : complete(value) {}
        void Invoke() noexcept override { complete.set_value(); }
    };
    std::promise<void> returned;
    coordinator->PostReserved(std::make_unique<Returned>(returned));
    returned.get_future().get();
    bool closed = false;
    try { net::co_spawn(a->Executor(), Join(a, b), net::use_future).get(); }
    catch (const std::system_error& error) { closed = error.code() == net::error::operation_aborted; }
    Require(closed, "closed coordinator admitted another merge");
    net::co_spawn(first, coordinator->AsyncJoin(), net::use_future).get();
    Require(live.load() == 4, "completed uploads retained domain hosts");
    a.reset(); b.reset(); c.reset(); independent.reset();
    net::co_spawn(first, [coordinator]() -> net::awaitable<void> {
        coordinator->ReleaseServices();
        co_await coordinator->Finalize();
    }, net::use_future).get();
    Require(live.load() == 0, "finalization retained domain hosts");
    coordinator.reset();
    first_work.reset(); second_work.reset(); third_work.reset();
    t0.join(); t1.join(); t2.join();
}

void FinalizeJoinsDomainRetirement() {
    net::io_context io;
    auto coordinator = std::make_shared<GroupCoordinator>(io);
    std::atomic<unsigned> live{0};
    auto domain = ExecutionDomain::Create(io, 0, io.get_executor(),
        std::make_shared<Hooks>(live), coordinator);
    const std::weak_ptr<ExecutionDomain> retired = domain;
    bool finalized = false;
    std::exception_ptr failure;
    auto shutdown = [&]() -> net::awaitable<void> {
        coordinator->CloseAdmission();
        co_await coordinator->AsyncJoin();
        coordinator->ReleaseServices();
        net::post(io, [&] {
            // Finalize must suspend while an owner can still publish its
            // preallocated retirement, not close the reserved return channel.
            Require(!finalized, "finalization completed before domain retirement");
            domain.reset();
        });
        co_await coordinator->Finalize();
        Require(retired.expired() && live.load() == 0, "finalization left a live domain");
        finalized = true;
    };
    net::co_spawn(io, shutdown(), [&](std::exception_ptr error) { failure = error; });
    io.run();
    if (failure) std::rethrow_exception(failure);
    Require(finalized, "finalization did not resume");
}
}

int main() {
    StableDomainOwnership();
    FinalizeJoinsDomainRetirement();
    std::cout << "session_group_executor_test passed\n";
}
