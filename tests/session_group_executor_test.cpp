#include <gtest/gtest.h>

#include "app/session_group_executor.hpp"

#include <asio/co_spawn.hpp>
#include <asio/bind_cancellation_slot.hpp>
#include <asio/cancellation_signal.hpp>
#include <asio/post.hpp>
#include <asio/redirect_error.hpp>
#include <asio/steady_timer.hpp>
#include <asio/use_future.hpp>
#include <atomic>
#include <cstdlib>
#include <future>
#include <iostream>
#include <stdexcept>
#include <thread>
#include <vector>

namespace {
void Require(bool condition, const char* message) {
    if (!condition) {
        std::cerr << message << '\n';
        std::abort();
    }
}

struct Hooks final : ExecutionDomain::Hooks {
    explicit Hooks(std::atomic<unsigned>& live, std::atomic<unsigned>* failures = nullptr)
        : live(live), failures(failures) { ++live; }
    ~Hooks() override { --live; }
    void Enter() noexcept override {
        Require(!entered.exchange(true), "domain acquired by concurrent owners");
    }
    void Leave() noexcept override {
        Require(entered.exchange(false), "domain released without an owner");
    }
    void OnFailure(std::exception_ptr) noexcept override {
        Require(entered.load(), "failure callback ran without native domain lease");
        if (!failures) std::terminate();
        ++*failures;
    }
    std::atomic<unsigned>& live;
    std::atomic<unsigned>* failures;
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
    coordinator->RegisterWorker(0, first, first.get_executor());
    coordinator->RegisterWorker(1, second, second.get_executor());
    coordinator->RegisterWorker(2, third, third.get_executor());
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

struct NativeProbe final : ExecutionDomain::NativeResource {
    std::shared_ptr<ExecutionDomain> domain;
    std::thread::id first_thread, second_thread;
    unsigned prepares = 0, commits = 0, cancels = 0;
    bool fail_prepare = false;
    bool fail_cancel = false;
    bool staged = false;
    NativeProbe(std::shared_ptr<ExecutionDomain> owner,
                std::thread::id first, std::thread::id second)
        : domain(std::move(owner)), first_thread(first), second_thread(second) {}
    void Check(uint32_t owner) {
        Require(ExecutionDomain::Current() == domain, "native control lost domain lease");
        Require(!domain->CanExecuteInline(), "native control permits business inline dispatch");
        Require(std::this_thread::get_id() == (owner == 0 ? first_thread : second_thread),
                "native control ran on wrong reactor");
    }
    net::awaitable<void> PrepareHandoff(const ExecutionDomain::HandoffTarget&) override {
        Check(domain->OwnerId());
        ++prepares;
        staged = true;
        co_await net::post(net::use_awaitable);
        Check(domain->OwnerId());
        if (fail_prepare) throw std::runtime_error("prepare failure");
    }
    void CommitHandoff(const ExecutionDomain::HandoffTarget& target) noexcept override {
        Check(target.worker_id);
        Require(staged, "committing unprepared resource");
        staged = false;
        ++commits;
    }
    net::awaitable<void> CancelHandoff(const ExecutionDomain::HandoffTarget& old) override {
        Check(old.worker_id);
        co_await net::post(net::use_awaitable);
        Check(old.worker_id);
        staged = false;
        ++cancels;
        if (fail_cancel) throw std::runtime_error("terminal rollback failure");
    }
};

void PassiveHandoffAndExclusiveDetach() {
    net::io_context first, second;
    auto first_work = net::make_work_guard(first);
    auto second_work = net::make_work_guard(second);
    auto coordinator = std::make_shared<GroupCoordinator>(first);
    coordinator->RegisterWorker(0, first, first.get_executor());
    coordinator->RegisterWorker(1, second, second.get_executor());
    std::atomic<unsigned> live{0};
    std::atomic<unsigned> failures{0};
    auto make = [&](net::io_context& io, uint32_t id) {
        return ExecutionDomain::Create(io, id, io.get_executor(),
            std::make_shared<Hooks>(live, &failures), coordinator);
    };
    auto request = make(first, 0);
    auto physical = make(first, 0);
    auto unrelated = make(first, 0);
    auto target_domain = make(second, 1);
    std::thread t0([&] { first.run(); });
    std::thread t1([&] { second.run(); });
    const auto old_thread = net::co_spawn(request->Executor(), ThreadId(), net::use_future).get();
    const auto new_thread = net::co_spawn(target_domain->Executor(), ThreadId(), net::use_future).get();
    const ExecutionDomain::HandoffTarget old_target{0, &first, first.get_executor()};
    const ExecutionDomain::HandoffTarget new_target{1, &second, second.get_executor()};
    NativeProbe native(physical, old_thread, new_thread);
    net::co_spawn(physical->Executor(), [&]() -> net::awaitable<void> {
        physical->RegisterResource(native);
        co_return;
    }, net::use_future).get();
    const auto identity = physical->LeaseIdentity();
    const auto request_identity = request->LeaseIdentity();
    Require(net::co_spawn(request->Executor(), request->AttachExclusive(physical), net::use_future).get(),
            "same-owner physical attachment was rejected");
    Require(ExecutionDomain::SharesLeaseIdentity(identity.get(), request_identity.get()),
            "attachment did not update retained lease identity");
    bool rejected = false;
    try {
        net::co_spawn(request->Executor(),
            request->PreparePassiveHandoff(new_target), net::use_future).get();
    } catch (const std::logic_error&) { rejected = true; }
    Require(rejected, "handoff admitted a waiter inside the frozen group");

    auto handoff = net::co_spawn(second,
        request->PreparePassiveHandoff(new_target), net::use_future).get();
    Require(request->OwnerId() == 0 && physical->OwnerId() == 0,
            "prepare prematurely published receiving owner");
    std::atomic<unsigned> delivered{0};
    std::promise<void> completed;
    request->Execute([&] { ++delivered; });
    net::co_spawn(second, handoff->Validate([&] {
        Require(ExecutionDomain::Current() == request, "validation lacks origin domain lease");
        Require(delivered.load() == 0, "business callback escaped preparation freeze");
        GroupExecutor(request).execute([&] {
            Require(std::this_thread::get_id() == new_thread, "validation completion lost target");
            ++delivered;
            completed.set_value();
        });
        Require(delivered.load() == 0, "validation executed business dispatch inline");
    }), net::use_future).get();
    net::co_spawn(second, handoff->Commit(), net::use_future).get();
    completed.get_future().get();
    Require(delivered.load() == 2, "handoff dropped admitted business completions");
    Require(&request->Reactor() == &second && request->OwnerId() == 1,
            "handoff did not publish actual receiving reactor");
    Require(physical->OwnerId() == 1 && unrelated->OwnerId() == 0,
            "handoff moved unrelated domain or omitted physical attachment");
    Require(native.prepares == 1 && native.commits == 1 && !native.staged,
            "native participant did not commit exactly once");
    handoff.reset();
    net::co_spawn(request->Executor(), request->DetachExclusive(physical), net::use_future).get();
    Require(physical->LeaseIdentity().get() == identity.get(), "detachment replaced stable identity");
    Require(!ExecutionDomain::SharesLeaseIdentity(identity.get(), request_identity.get()),
            "detachment retained shared allocation lease");
    handoff = net::co_spawn(first,
        request->PreparePassiveHandoff(old_target), net::use_future).get();
    net::co_spawn(first, handoff->Commit(), net::use_future).get();
    handoff.reset();
    Require(physical->OwnerId() == 1, "detached physical domain followed former borrower");
    Require(!net::co_spawn(request->Executor(),
        request->AttachExclusive(physical), net::use_future).get(),
        "pool reuse initiated a cross-owner migration");
    Require(request->OwnerId() == 0 && physical->OwnerId() == 1 && native.commits == 1,
            "rejected reuse changed native ownership");
    Require(net::co_spawn(target_domain->Executor(),
        target_domain->AttachExclusive(physical), net::use_future).get(),
        "healthy migrated resource was not reusable on its current owner");
    net::co_spawn(target_domain->Executor(),
        target_domain->DetachExclusive(physical), net::use_future).get();
    // A later receive-path handoff, not a pool borrow, can change ownership.
    handoff = net::co_spawn(first,
        physical->PreparePassiveHandoff(old_target), net::use_future).get();
    net::co_spawn(first, handoff->Commit(), net::use_future).get();
    handoff.reset();
    Require(net::co_spawn(request->Executor(),
        request->AttachExclusive(physical), net::use_future).get(),
        "same-owner reuse after passive handoff failed");
    Require(native.commits == 2, "passive handoff did not move the native resource");
    for (unsigned i = 0; i != 64; ++i) {
        net::co_spawn(request->Executor(), request->DetachExclusive(physical), net::use_future).get();
        Require(!request->SharesGroup(*physical), "repeated detach retained ancestry");
        Require(net::co_spawn(request->Executor(),
            request->AttachExclusive(physical), net::use_future).get(),
            "same-owner reattachment was rejected");
        Require(physical->LeaseIdentity().get() == identity.get(), "repeated attach replaced identity");
    }

    // Validation may consume protocol state; cancelling must preserve and
    // resume its admitted callbacks on the old owner, not discard them.
    handoff = net::co_spawn(second,
        request->PreparePassiveHandoff(new_target), net::use_future).get();
    std::promise<void> restored;
    bool validation_failed = false;
    try {
        net::co_spawn(second, handoff->Validate([&] {
            request->Execute([&] {
                Require(std::this_thread::get_id() == old_thread, "cancel resumed on candidate owner");
                restored.set_value();
            });
            throw std::runtime_error("authentication failed");
        }), net::use_future).get();
    } catch (const std::runtime_error&) { validation_failed = true; }
    Require(validation_failed, "failed protocol validation was suppressed");
    net::co_spawn(second, handoff->Cancel(), net::use_future).get();
    restored.get_future().get();
    handoff.reset();
    Require(request->OwnerId() == 0 && native.cancels == 1,
            "failed validation did not restore original owner");

    native.fail_prepare = true;
    bool preparation_failed = false;
    try {
        net::co_spawn(second, request->PreparePassiveHandoff(new_target), net::use_future).get();
    } catch (const std::runtime_error&) { preparation_failed = true; }
    Require(preparation_failed && native.cancels == 2 && !native.staged,
            "partially prepared native resource was not rolled back");
    Require(net::co_spawn(request->Executor(), ThreadId(), net::use_future).get() == old_thread,
            "prepare failure stranded frozen business executor");
    native.fail_prepare = false;

    handoff = net::co_spawn(second,
        request->PreparePassiveHandoff(new_target), net::use_future).get();
    native.fail_cancel = true;
    bool rollback_failed = false;
    try { net::co_spawn(second, handoff->Cancel(), net::use_future).get(); }
    catch (const std::runtime_error&) { rollback_failed = true; }
    Require(rollback_failed && !native.staged && failures.load() == 2,
            "terminal rollback failure was not contained to the attached session");
    handoff.reset();
    native.fail_cancel = false;
    Require(net::co_spawn(request->Executor(), ThreadId(), net::use_future).get() == old_thread,
            "terminal rollback stranded admitted teardown completions");

    auto shared_a = make(first, 0);
    auto shared_b = make(first, 0);
    net::co_spawn(shared_a->Executor(), shared_a->Join(shared_b), net::use_future).get();
    bool shared_rejected = false;
    try {
        net::co_spawn(request->Executor(), request->AttachExclusive(shared_a), net::use_future).get();
    } catch (const std::logic_error&) { shared_rejected = true; }
    Require(shared_rejected && !request->SharesGroup(*shared_a),
            "exclusive attachment captured a permanently shared physical domain");
    shared_a.reset(); shared_b.reset();

    handoff = net::co_spawn(second,
        request->PreparePassiveHandoff(new_target), net::use_future).get();
    coordinator->CloseAdmission();
    // Resolution of an already admitted transaction must survive admission
    // closure; shutdown cannot strand a native resource or its execution token.
    net::co_spawn(second, handoff->Cancel(), net::use_future).get();
    handoff.reset();
    net::co_spawn(request->Executor(), [&]() -> net::awaitable<void> {
        physical->UnregisterResource(native);
        co_return;
    }, net::use_future).get();
    native.domain.reset();
    net::co_spawn(first, coordinator->AsyncJoin(), net::use_future).get();
    request.reset(); physical.reset(); unrelated.reset(); target_domain.reset();
    net::co_spawn(first, [coordinator]() -> net::awaitable<void> {
        coordinator->ReleaseServices();
        co_await coordinator->Finalize();
    }, net::use_future).get();
    Require(live.load() == 0, "handoff retained domain hosts at finalization");
    coordinator.reset();
    first_work.reset(); second_work.reset();
    t0.join(); t1.join();
}

void FinalizeJoinsDomainRetirement() {
    net::io_context io;
    auto coordinator = std::make_shared<GroupCoordinator>(io);
    coordinator->RegisterWorker(0, io, io.get_executor());
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

void HandoffCompletionWaitsForNativeLease() {
    struct LeaseHooks final : ExecutionDomain::Hooks {
        std::atomic<bool> entered{false};
        bool pause = false;
        std::promise<void> leaving;
        std::shared_future<void> release;
        void Enter() noexcept override {
            Require(!entered.exchange(true), "handoff overlapped native execution");
        }
        void Leave() noexcept override {
            if (std::exchange(pause, false)) {
                leaving.set_value();
                release.wait();
            }
            entered.store(false);
        }
        void OnFailure(std::exception_ptr) noexcept override { std::terminate(); }
    };
    struct Resource final : ExecutionDomain::NativeResource {
        LeaseHooks& hooks;
        explicit Resource(LeaseHooks& value) : hooks(value) {}
        net::awaitable<void> PrepareHandoff(const ExecutionDomain::HandoffTarget&) override {
            co_await net::post(net::use_awaitable);
            hooks.pause = true;
        }
        void CommitHandoff(const ExecutionDomain::HandoffTarget&) noexcept override {}
        net::awaitable<void> CancelHandoff(const ExecutionDomain::HandoffTarget&) override {
            co_await net::post(net::use_awaitable);
            hooks.pause = true;
        }
    };
    net::io_context control, source, target;
    auto control_work = net::make_work_guard(control);
    auto source_work = net::make_work_guard(source);
    auto target_work = net::make_work_guard(target);
    auto coordinator = std::make_shared<GroupCoordinator>(control);
    coordinator->RegisterWorker(0, source, source.get_executor());
    coordinator->RegisterWorker(1, target, target.get_executor());
    auto hooks = std::make_shared<LeaseHooks>();
    auto domain = ExecutionDomain::Create(source, 0, source.get_executor(), hooks, coordinator);
    Resource resource(*hooks);
    std::thread control_thread([&] { control.run(); });
    std::thread source_thread([&] { source.run(); });
    std::thread target_thread([&] { target.run(); });
    net::co_spawn(domain->Executor(), [&]() -> net::awaitable<void> {
        domain->RegisterResource(resource);
        co_return;
    }, net::use_future).get();

    std::promise<void> release_prepare;
    hooks->release = release_prepare.get_future().share();
    auto leaving = hooks->leaving.get_future();
    auto preparing = net::co_spawn(control, domain->PreparePassiveHandoff(
        {1, &target, target.get_executor()}), net::use_future);
    leaving.get();
    const bool prepare_waited =
        preparing.wait_for(std::chrono::milliseconds(100)) == std::future_status::timeout;
    release_prepare.set_value();
    auto handoff = preparing.get();
    Require(prepare_waited, "prepare completed before its native lease exited");
    net::co_spawn(control, handoff->Validate([&] {
        Require(hooks->entered.load(), "validation lacked an exclusive lease");
    }), net::use_future).get();

    std::promise<void> release_cancel;
    hooks->release = release_cancel.get_future().share();
    hooks->leaving = {};
    leaving = hooks->leaving.get_future();
    auto cancelling = net::co_spawn(control, handoff->Cancel(), net::use_future);
    leaving.get();
    const bool cancel_waited =
        cancelling.wait_for(std::chrono::milliseconds(100)) == std::future_status::timeout;
    release_cancel.set_value();
    cancelling.get();
    Require(cancel_waited, "rollback completed before its native lease exited");
    net::co_spawn(domain->Executor(), [&]() -> net::awaitable<void> {
        domain->UnregisterResource(resource);
        co_return;
    }, net::use_future).get();
    handoff.reset();
    domain.reset();
    coordinator->CloseAdmission();
    net::co_spawn(control, coordinator->AsyncJoin(), net::use_future).get();
    net::co_spawn(control, [&]() -> net::awaitable<void> {
        coordinator->ReleaseServices();
        co_await coordinator->Finalize();
    }, net::use_future).get();
    coordinator.reset();
    control_work.reset(); source_work.reset(); target_work.reset();
    control_thread.join(); source_thread.join(); target_thread.join();
}
}

TEST(SessionGroupExecutor, Contract) {
    StableDomainOwnership();
    FinalizeJoinsDomainRetirement();
    PassiveHandoffAndExclusiveDetach();
    HandoffCompletionWaitsForNativeLease();
    std::cout << "session_group_executor_test passed\n";
}
