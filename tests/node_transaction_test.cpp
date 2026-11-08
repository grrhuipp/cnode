#include <gtest/gtest.h>

#include "node_transaction.hpp"

#include <asio/co_spawn.hpp>
#include <asio/bind_cancellation_slot.hpp>
#include <asio/cancellation_signal.hpp>
#include <asio/post.hpp>
#include <asio/steady_timer.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/use_future.hpp>

#include <chrono>
#include <functional>
#include <future>
#include <iostream>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
namespace net = ::net;
using namespace ::controller;
using ::api::NodeInfo;
using ::proxyman::inbound::UserSet;

void Require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

std::string Tag(const NodeInfo& config) {
    return config.NodeType + ':' + std::to_string(config.Port);
}

std::shared_ptr<const NodeSnapshot> Snapshot(uint16_t port, size_t version = 1) {
    auto snapshot = std::make_shared<NodeSnapshot>();
    snapshot->config.Port = port;
    snapshot->config.Path = std::to_string(version);
    snapshot->protocol = snapshot->config.NodeType;
    snapshot->tag = Tag(snapshot->config);
    snapshot->users.resize(version);
    snapshot->users_etag = "users-" + std::to_string(version);
    snapshot->config_etag = "config-" + std::to_string(version);
    snapshot->rules.resize(version);
    ::StreamSettings stream;
    stream.ws.path = snapshot->config.Path;
    snapshot->inbound = std::make_shared<const ::PreparedInbound>(::PreparedInbound{
        .binding = {.port = port, .protocol = snapshot->protocol, .tag = snapshot->tag, .listen = {}},
        .receiver = ::proxyman::inbound::MakeReceiverSettings(
            snapshot->tag, {}, snapshot->protocol, std::move(stream), {},
            ::ProxyProtocolMode::Auto, ::routing::RouteWithFallback(snapshot->tag), {}),
        .build_request = {},
        .users = std::make_shared<const UserSet>(
            ::proxyman::inbound::PreparedVmessUsers(version)),
    });
    auto outbound = std::make_shared<::proxyman::outbound::PreparedOutboundConfig>();
    outbound->tag = snapshot->tag;
    snapshot->outbound = std::move(outbound);
    return snapshot;
}

// A users-only change keeps every prepared setting and replaces the users.
void ReplaceUsers(NodeSnapshot& snapshot, size_t count) {
    auto inbound = std::make_shared<::PreparedInbound>(*snapshot.inbound);
    inbound->users = std::make_shared<const UserSet>(
        ::proxyman::inbound::PreparedVmessUsers(count));
    snapshot.inbound = std::move(inbound);
}

PreparedNodeChange Change(std::shared_ptr<const NodeSnapshot> next, const NodeState&) {
    PreparedNodeChange change;
    change.next = std::move(next);
    return change;
}

struct Resources {
    bool inbound = false;
    bool outbound = false;
    size_t users = 0;
    size_t rules = 0;
    std::string version;
};

struct Fault {
    std::string operation;
    int occurrence = 1;
    bool after_mutation = false;
    bool return_false = false;
};

struct MutationFailure : std::runtime_error {
    explicit MutationFailure(std::string operation)
        : std::runtime_error("injected mutation failure"), operation(std::move(operation)) {}
    std::string operation;
};

// The transaction is the production implementation. Only its concrete runtime
// operations are replaced, including failures after a partial mutation.
struct Runtime {
    std::map<std::string, Resources> resources;
    std::map<std::string, int> counts;
    std::vector<std::string> calls;
    std::vector<Fault> faults;
    net::steady_timer* inbound_gate = nullptr;
    bool gate_entered = false;
    bool gate_released = false;
    bool closed = false;
    size_t operations_started = 0;

    [[nodiscard]] bool IsStopping() const noexcept { return closed; }

    bool Step(std::string operation, const std::function<void()>& mutate) {
        if (closed) throw ::IoSystemError(net::error::operation_aborted);
        calls.push_back(operation);
        const int occurrence = ++counts[operation];
        const Fault* fault = nullptr;
        for (const auto& candidate : faults) {
            if (candidate.operation == operation && candidate.occurrence == occurrence) fault = &candidate;
        }
        if (fault && !fault->after_mutation) {
            if (fault->return_false) return false;
            throw MutationFailure(operation);
        }
        mutate();
        if (fault) {
            if (fault->return_false) return false;
            throw MutationFailure(operation);
        }
        return true;
    }

    net::awaitable<void> RemoveInbound(const std::string& tag) {
        ++operations_started;
        co_await net::post(net::use_awaitable);
        Step("remove-in:" + tag, [&] { resources[tag].inbound = false; });
    }
    net::awaitable<void> RemoveOutbound(const std::string& tag) {
        ++operations_started;
        co_await net::post(net::use_awaitable);
        Step("remove-out:" + tag, [&] { resources[tag].outbound = false; });
    }
    net::awaitable<bool> AddInbound(const ::PreparedInbound& inbound) {
        ++operations_started;
        co_await net::post(net::use_awaitable);
        if (inbound_gate) {
            struct Release {
                Runtime& runtime;
                ~Release() { runtime.gate_released = true; }
            } release{*this};
            gate_entered = true;
            co_await inbound_gate->async_wait(net::use_awaitable);
        }
        const auto& tag = inbound.binding.tag;
        co_return Step("add-in:" + tag, [&] {
            resources[tag].inbound = true;
            resources[tag].version = inbound.receiver.stream_settings.ws.path;
        });
    }
    net::awaitable<void> AddOutbound(const ::proxyman::outbound::PreparedOutboundConfig& outbound) {
        ++operations_started;
        co_await net::post(net::use_awaitable);
        const auto& tag = outbound.tag;
        Step("add-out:" + tag, [&] { resources[tag].outbound = true; });
    }
    net::awaitable<void> UpdateRules(const std::string& tag, const std::vector<::rule::DetectRule>& rules) {
        ++operations_started;
        co_await net::post(net::use_awaitable);
        Step("rules:" + tag, [&] { resources[tag].rules = rules.size(); });
    }
    net::awaitable<void> ApplyUsers(const std::string& tag, const UserSet& users) {
        ++operations_started;
        Step("users:" + tag, [&] {
            resources[tag].users = std::visit([](const auto& values) { return values.size(); }, users);
        });
        co_return;
    }
    net::awaitable<void> RecoverUsers() {
        ++operations_started;
        co_return;
    }
    net::awaitable<void> ClearUsers(const std::string& tag, const std::string&) {
        ++operations_started;
        Step("clear-users:" + tag, [&] { resources[tag].users = 0; });
        co_return;
    }
};

std::exception_ptr Run(net::awaitable<void> task) {
    net::io_context io;
    auto result = net::co_spawn(io, std::move(task), net::use_future);
    io.run();
    try { result.get(); }
    catch (...) { return std::current_exception(); }
    return {};
}

void Seed(Runtime& runtime, NodeState& state, std::shared_ptr<const NodeSnapshot> snapshot) {
    state.committed = snapshot;
    state.phase = NodeRuntimePhase::Ready;
    runtime.resources[snapshot->tag] = {
        true, true, snapshot->users.size(), snapshot->rules.size(), snapshot->config.Path};
}

bool Matches(const Runtime& runtime, const NodeSnapshot& snapshot) {
    const auto& actual = runtime.resources.at(snapshot.tag);
    return actual.inbound && actual.outbound && actual.users == snapshot.users.size() &&
        actual.rules == snapshot.rules.size() && actual.version == snapshot.config.Path;
}

bool Empty(const Runtime& runtime, const std::string& tag) {
    const auto it = runtime.resources.find(tag);
    return it == runtime.resources.end() ||
        (!it->second.inbound && !it->second.outbound && it->second.users == 0 && it->second.rules == 0);
}

void TestSuccessAndRefresh() {
    Runtime runtime;
    NodeState state;
    auto first = Snapshot(1000);
    Require(!Run(ApplyNodeChange(runtime, state, Change(first, state))), "create failed");
    auto refresh = std::make_shared<NodeSnapshot>(*first);
    refresh->users.resize(2);
    ReplaceUsers(*refresh, 2);
    refresh->users_etag = "users-2";
    refresh->rules.resize(2);
    Require(!Run(ApplyNodeChange(runtime, state, Change(refresh, state))), "refresh failed");
    Require(state.committed == refresh && state.phase == NodeRuntimePhase::Ready &&
        !state.HasPendingCleanup() && Matches(runtime, *refresh), "refresh must publish the complete new snapshot");
    Require(runtime.counts["add-in:" + first->tag] == 1, "refresh must preserve the existing listener");
    Require(first->users.size() == 1 && first->rules.size() == 1, "published old snapshots must remain immutable");
    Require(state.committed->users_etag == "users-2" && first->users_etag == "users-1",
        "user validators must be published with their immutable snapshot");
}

void TestFailureMatrix() {
    const auto old = Snapshot(1000);
    const auto next = Snapshot(2000, 2);
    const std::vector<std::string> operations{
        "users:" + next->tag, "add-out:" + next->tag, "add-in:" + next->tag,
        "remove-in:" + old->tag, "remove-out:" + old->tag,
        "clear-users:" + old->tag, "rules:" + old->tag, "rules:" + next->tag};
    for (const auto& operation : operations) {
        for (const bool after : {false, true}) {
            Runtime runtime;
            NodeState state;
            Seed(runtime, state, old);
            runtime.faults.push_back({operation, 1, after, false});
            const auto failure = Run(ApplyNodeChange(runtime, state, Change(next, state)));
            Require(static_cast<bool>(failure), "injected mutation must fail the change");
            try { std::rethrow_exception(failure); }
            catch (const MutationFailure& error) {
                Require(error.operation == operation, "rollback must preserve the original failure");
            }
            Require(state.committed == old && state.phase == NodeRuntimePhase::Ready &&
                !state.HasPendingCleanup() && Matches(runtime, *old) && Empty(runtime, next->tag),
                "every single transition failure must restore the old runtime and remove the candidate");
            Require(state.committed->users_etag == "users-1" &&
                state.committed->config_etag == "config-1",
                "a failed update must not acknowledge fetched user or config validators");
        }
    }
    for (const auto& operation : {"add-in:" + next->tag}) {
        for (const bool after : {false, true}) {
            Runtime runtime;
            NodeState state;
            Seed(runtime, state, old);
            runtime.faults.push_back({operation, 1, after, true});
            Require(static_cast<bool>(Run(ApplyNodeChange(runtime, state, Change(next, state)))) &&
                state.committed == old && state.phase == NodeRuntimePhase::Ready &&
                Matches(runtime, *old) && Empty(runtime, next->tag),
                "a false mutation result must roll back partial effects like an exception");
        }
    }
}

void TestRefreshRollbackFailure() {
    Runtime runtime;
    NodeState state;
    const auto old = Snapshot(1000);
    auto next = std::make_shared<NodeSnapshot>(*old);
    next->users.resize(2);
    ReplaceUsers(*next, 2);
    next->rules.resize(2);
    Seed(runtime, state, old);
    runtime.faults = {{"users:" + old->tag, 1, true}, {"rules:" + old->tag, 2, false}};
    Require(static_cast<bool>(Run(ApplyNodeChange(runtime, state, Change(next, state)))) &&
        state.committed == old && state.phase == NodeRuntimePhase::RecoveryRequired &&
        runtime.resources.at(old->tag).rules == 2, "failed refresh compensation must invalidate partially updated rules");
    runtime.faults.clear();
    Require(!Run(ApplyNodeChange(runtime, state, Change(old, state))) && Matches(runtime, *old) &&
        runtime.counts["add-in:" + old->tag] == 1, "recovery must rebuild after a partial refresh even when the old listener survived");
}

void TestFailedRollbackForcesRebuild() {
    Runtime runtime;
    NodeState state;
    const auto old = Snapshot(1000);
    const auto next = Snapshot(1000, 2);
    Seed(runtime, state, old);
    runtime.faults = {{"rules:" + old->tag, 1, true}, {"add-in:" + old->tag, 2, false}};
    Require(static_cast<bool>(Run(ApplyNodeChange(runtime, state, Change(next, state)))), "double fault must fail");
    Require(state.committed == old && state.phase == NodeRuntimePhase::RecoveryRequired && state.HasPendingCleanup(),
        "failed rollback must invalidate runtime readiness without losing the last committed snapshot");
    Require(!runtime.resources.at(old->tag).inbound, "the injected rollback failure must actually leave the listener absent");
    const auto installs = runtime.counts["add-in:" + old->tag];
    runtime.faults.clear();
    Require(!Run(ApplyNodeChange(runtime, state, Change(old, state))), "recovery of identical config failed");
    Require(runtime.counts["add-in:" + old->tag] > installs && Matches(runtime, *old) &&
        state.phase == NodeRuntimePhase::Ready && !state.HasPendingCleanup(),
        "identical config after failed rollback must rebuild instead of only refreshing users and rules");
}

void TestOrphanCleanupAndBlockedRetry() {
    Runtime runtime;
    NodeState state;
    const auto old = Snapshot(1000);
    const auto next = Snapshot(2000, 2);
    const auto later = Snapshot(3000, 3);
    Seed(runtime, state, old);
    runtime.faults = {{"add-in:" + next->tag, 1, true}, {"remove-in:" + next->tag, 1, false}};
    Require(static_cast<bool>(Run(ApplyNodeChange(runtime, state, Change(next, state)))), "orphan fixture must fail");
    Require(runtime.resources.at(next->tag).inbound && state.HasPendingCleanup(), "failed candidate cleanup must be retained");
    runtime.faults = {{"remove-out:" + old->tag, runtime.counts["remove-out:" + old->tag] + 1, true}};
    Require(static_cast<bool>(Run(ApplyNodeChange(runtime, state, Change(later, state)))), "blocked cleanup must fail the retry");
    Require(Empty(runtime, later->tag) && state.committed == old && state.HasPendingCleanup(),
        "a new candidate must not start while earlier resources still need cleanup");
    runtime.faults.clear();
    Require(!Run(ApplyNodeChange(runtime, state, Change(later, state))), "retry after cleanup failure must recover");
    Require(Empty(runtime, old->tag) && Empty(runtime, next->tag) && Matches(runtime, *later) &&
        state.committed == later && !state.HasPendingCleanup(), "recovery must remove both old and orphan candidate resources");
}

void TestCleanupFailureRecovery() {
    Runtime runtime;
    NodeState state;
    const auto old = Snapshot(1000);
    Seed(runtime, state, old);
    state.pending_cleanup = {old, {}};
    runtime.faults = {{"remove-out:" + old->tag, 1, true}};
    Require(static_cast<bool>(Run(CleanPendingNodeRuntime(runtime, state))), "partial cleanup must fail");
    Require(state.committed == old && state.phase == NodeRuntimePhase::RecoveryRequired &&
        state.HasPendingCleanup() && !runtime.resources.at(old->tag).inbound, "partial removal must preserve recovery data");
    runtime.faults.clear();
    Require(!Run(ApplyNodeChange(runtime, state, Change(old, state))) && Matches(runtime, *old),
        "a node must be rebuilt after partial cleanup");
    Require(state.committed->users_etag == "users-1",
        "cleanup and recovery must retain the last committed user validator");
}

void TestUncommittedCandidateCleanup() {
    Runtime runtime;
    NodeState state;
    const auto next = Snapshot(2000);
    runtime.faults = {{"add-in:" + next->tag, 1, true}, {"remove-in:" + next->tag, 1, false}};
    Require(static_cast<bool>(Run(ApplyNodeChange(runtime, state, Change(next, state)))) &&
        !state.committed && state.HasPendingCleanup(), "failed initial creation must retain cleanup without a committed node");
    runtime.faults.clear();
    Require(!Run(CleanPendingNodeRuntime(runtime, state)) && !state.HasPendingCleanup() && Empty(runtime, next->tag),
        "local cleanup must remove an uncommitted orphan candidate");
}

void TestReservationBeforeFirstSuspend() {
    Runtime runtime;
    NodeState state;
    const auto old = Snapshot(1000);
    const auto next = Snapshot(2000);
    Seed(runtime, state, old);
    net::io_context io;
    auto completed = net::co_spawn(io, ApplyNodeChange(runtime, state, Change(next, state)), net::use_future);
    Require(io.poll_one() == 1 && state.phase == NodeRuntimePhase::Updating &&
        state.ReservesPort(1000) && state.ReservesPort(2000),
        "clean transaction entry must reserve both endpoints before its first suspension");
    io.run();
    completed.get();
    Require(!state.ReservesPort(1000) && state.ReservesPort(2000),
        "successful transition must release the old endpoint");
    Require(!Run(CleanPendingNodeRuntime(runtime, state)), "empty cleanup must succeed");
    state.phase = NodeRuntimePhase::Stopped;
    Require(!state.ReservesPort(2000), "stopped historical data must not reserve a cleaned endpoint");
}

void TestCancellationRollback(bool close_runtime) {
    Runtime runtime;
    NodeState state;
    const auto old = Snapshot(1000);
    const auto next = Snapshot(2000);
    Seed(runtime, state, old);
    net::io_context io;
    net::steady_timer gate(io, net::steady_timer::time_point::max());
    runtime.inbound_gate = &gate;
    net::cancellation_signal cancellation;
    bool completed = false;
    std::exception_ptr failure;
    net::co_spawn(io, ApplyNodeChange(runtime, state, Change(next, state)),
        net::bind_cancellation_slot(cancellation.slot(), [&](std::exception_ptr error) {
            completed = true;
            failure = error;
        }));
    io.poll();
    Require(runtime.gate_entered && !completed, "cancellation fixture must suspend after earlier mutations");
    Require(state.ReservesPort(1000) && state.ReservesPort(2000),
        "an in-flight transaction must reserve old and candidate endpoints");
    const auto started_before_stop = runtime.operations_started;
    cancellation.emit(net::cancellation_type::terminal);
    runtime.closed = close_runtime;
    io.run();
    Require(completed && failure && runtime.gate_released && state.committed == old,
        "cancelled mutation must release the active operation and preserve the committed snapshot");
    if (close_runtime) {
        Require(state.phase == NodeRuntimePhase::RecoveryRequired && state.HasPendingCleanup() &&
            state.ReservesPort(1000) && state.ReservesPort(2000),
            "closed mutation admission must retain unfinished cleanup and reservations");
        Require(runtime.operations_started == started_before_stop,
            "shutdown must join the started operation without starting compensation");
    } else {
        Require(state.phase == NodeRuntimePhase::Ready && !state.HasPendingCleanup() &&
            Matches(runtime, *old) && Empty(runtime, next->tag) && !state.ReservesPort(2000),
            "rollback must ignore pull cancellation and restore the last committed runtime");
    }
    try { std::rethrow_exception(failure); }
    catch (const std::system_error& error) {
        Require(error.code() == net::error::operation_aborted, "cancellation must preserve its original cause");
    }
    runtime.inbound_gate = nullptr;
    runtime.closed = false;
    Require(!Run(ApplyNodeChange(runtime, state, Change(old, state))) && Matches(runtime, *old) &&
        Empty(runtime, next->tag), "a fresh attempt must repair the state left by a cancelled transaction");
    Require(state.ReservesPort(1000) && !state.ReservesPort(2000),
        "completed recovery must release the abandoned candidate endpoint");
    state.pending_cleanup = {old, {}};
    Require(!Run(CleanPendingNodeRuntime(runtime, state)) && !state.ReservesPort(1000),
        "completed cleanup must release the original endpoint");
}

net::awaitable<void> RecoverThenWait(Runtime& runtime, NodeState& state,
                                   PreparedNodeChange change, net::steady_timer& wait,
                                   bool& recovered) {
    bool failed = false;
    try {
        co_await ApplyNodeChange(runtime, state, std::move(change));
    } catch (const MutationFailure&) {
        failed = true;
    }
    Require(failed && state.phase == NodeRuntimePhase::Ready,
            "ordinary failure must finish rollback before the next pull");
    recovered = true;
    co_await wait.async_wait(net::use_awaitable);
}

void TestRollbackDoesNotDisableFutureStop() {
    Runtime runtime;
    NodeState state;
    const auto old = Snapshot(1000);
    const auto next = Snapshot(2000);
    Seed(runtime, state, old);
    runtime.faults.push_back({"add-in:" + next->tag});
    net::io_context io;
    net::steady_timer wait(io, net::steady_timer::time_point::max());
    net::cancellation_signal stop;
    bool recovered = false;
    bool completed = false;
    std::exception_ptr failure;
    net::co_spawn(io, RecoverThenWait(runtime, state, Change(next, state), wait, recovered),
        net::bind_cancellation_slot(stop.slot(), [&](std::exception_ptr error) {
            completed = true;
            failure = error;
        }));
    io.poll();
    Require(recovered && !completed, "the next pull must wait after rollback");
    stop.emit(net::cancellation_type::terminal);
    io.poll();
    const bool stopped = completed;
    if (!stopped) {
        wait.cancel();
        io.run();
    }
    Require(stopped && failure, "rollback shielding must not suppress a later stop");
    try { std::rethrow_exception(failure); }
    catch (const std::system_error& error) {
        Require(error.code() == net::error::operation_aborted,
                "later stop must retain cancellation semantics");
    }
}
void TestIncompleteCandidatePreservesLiveService() {
    Runtime runtime;
    NodeState state;
    const auto old = Snapshot(1000);
    Seed(runtime, state, old);
    auto next = std::make_shared<NodeSnapshot>(*Snapshot(1000, 2));
    next->inbound.reset();
    Require(static_cast<bool>(Run(ApplyNodeChange(runtime, state, Change(next, state)))),
        "an unprepared candidate must be rejected");
    Require(runtime.calls.empty() && state.committed == old &&
        state.phase == NodeRuntimePhase::Ready && Matches(runtime, *old),
        "candidate rejection must not retire the listener, users, outbound or rules");
}

net::awaitable<void> GatedChange(
    NodeMutationGate& gate, NodeMutationGate::Participant& participant,
    Runtime& runtime, NodeState& state, std::shared_ptr<const NodeSnapshot> next,
    std::vector<int>& committed, int panel, net::steady_timer* hold = nullptr) {
    auto lease = co_await gate.Acquire(participant);
    if (hold) {
        (void)co_await hold->async_wait(net::as_tuple(net::use_awaitable));
    }
    co_await ApplyNodeChange(runtime, state, Change(std::move(next), state));
    committed.push_back(panel);
}

net::awaitable<void> TwoGatedChanges(
    NodeMutationGate& gate, NodeMutationGate::Participant& participant,
    Runtime& runtime, NodeState& state, std::vector<int>& committed,
    net::steady_timer& hold) {
    co_await GatedChange(gate, participant, runtime, state, Snapshot(1000), committed, 1, &hold);
    co_await GatedChange(gate, participant, runtime, state, Snapshot(1000, 2), committed, 1);
}

net::awaitable<void> GatedCleanup(
    NodeMutationGate& gate, NodeMutationGate::Participant& participant,
    Runtime& runtime, NodeState& state) {
    auto lease = co_await gate.Acquire(participant);
    co_await CleanPendingNodeRuntime(runtime, state);
}

void RequireCancelled(std::future<void>& result) {
    Require(result.wait_for(std::chrono::seconds::zero()) == std::future_status::ready,
        "cancelled admission must complete without waiting for the active panel");
    try {
        result.get();
        Require(false, "waiting panel must report cancellation");
    } catch (const std::system_error& error) {
        Require(error.code() == net::error::operation_aborted,
            "waiting panel cancellation must retain operation_aborted");
    }
}

void TestFairMultiPanelTransactions() {
    net::io_context io;
    NodeMutationGate gate;
    NodeState first, second, third;
    NodeMutationGate::Participant one(gate, io.get_executor(), first);
    NodeMutationGate::Participant two(gate, io.get_executor(), second);
    NodeMutationGate::Participant three(gate, io.get_executor(), third);
    gate.Seal();
    Runtime runtime;
    std::vector<int> committed;
    net::steady_timer hold(io, net::steady_timer::time_point::max());
    auto first_done = net::co_spawn(io,
        TwoGatedChanges(gate, one, runtime, first, committed, hold), net::use_future);
    io.poll();
    auto second_done = net::co_spawn(io,
        GatedChange(gate, two, runtime, second, Snapshot(2000), committed, 2), net::use_future);
    auto third_done = net::co_spawn(io,
        GatedChange(gate, three, runtime, third, Snapshot(3000), committed, 3), net::use_future);
    io.poll();
    Require(runtime.calls.empty() && !first.committed && !second.committed && !third.committed,
        "waiting transactions must not mutate runtime or acknowledge fetched validators");
    auto duplicate = net::co_spawn(io,
        GatedChange(gate, two, runtime, second, Snapshot(4000), committed, 4), net::use_future);
    io.poll();
    Require(duplicate.wait_for(std::chrono::seconds::zero()) == std::future_status::ready,
        "duplicate admission must be rejected without adding another wait slot");
    bool rejected = false;
    try { duplicate.get(); }
    catch (const std::logic_error&) { rejected = true; }
    Require(rejected, "each fixed panel may own at most one pending admission");
    hold.cancel();
    io.run();
    first_done.get();
    second_done.get();
    third_done.get();
    Require(committed == std::vector<int>({1, 2, 3, 1}),
        "a fast polling panel must not overtake already waiting panels");
    Require(Matches(runtime, *first.committed) && Matches(runtime, *second.committed) &&
        Matches(runtime, *third.committed) && first.committed->config_etag == "config-2",
        "serialized publications must preserve every companion and commit validators with runtime");
}

void TestCancelledPanelRetainsQueueFairness() {
    net::io_context io;
    NodeMutationGate gate;
    NodeState first, second, third;
    NodeMutationGate::Participant one(gate, io.get_executor(), first);
    NodeMutationGate::Participant two(gate, io.get_executor(), second);
    NodeMutationGate::Participant three(gate, io.get_executor(), third);
    gate.Seal();
    Runtime runtime;
    std::vector<int> committed;
    net::steady_timer hold(io, net::steady_timer::time_point::max());
    auto first_done = net::co_spawn(io,
        GatedChange(gate, one, runtime, first, Snapshot(1000), committed, 1, &hold), net::use_future);
    io.poll();
    net::cancellation_signal cancellation;
    auto cancelled = net::co_spawn(io,
        GatedChange(gate, two, runtime, second, Snapshot(2000), committed, 2),
        net::bind_cancellation_slot(cancellation.slot(), net::use_future));
    auto third_done = net::co_spawn(io,
        GatedChange(gate, three, runtime, third, Snapshot(3000), committed, 3), net::use_future);
    io.poll();
    cancellation.emit(net::cancellation_type::terminal);
    io.poll();
    RequireCancelled(cancelled);
    auto retried = net::co_spawn(io,
        GatedChange(gate, two, runtime, second, Snapshot(2000), committed, 2), net::use_future);
    io.poll();
    hold.cancel();
    io.run();
    first_done.get();
    third_done.get();
    retried.get();
    Require(committed == std::vector<int>({1, 3, 2}),
        "a cancelled slot must detach and rejoin behind existing waiters");
}

void TestRecoveryOwnershipBlocksCompanions(bool close_gate) {
    net::io_context io;
    NodeMutationGate gate;
    NodeState owner, companion;
    NodeMutationGate::Participant one(gate, io.get_executor(), owner);
    NodeMutationGate::Participant two(gate, io.get_executor(), companion);
    gate.Seal();
    Runtime runtime;
    const auto old = Snapshot(1000);
    const auto next = Snapshot(2000, 2);
    const auto companion_snapshot = Snapshot(3000);
    Seed(runtime, owner, old);
    runtime.faults = {{"add-in:" + next->tag, 1, true}, {"remove-in:" + next->tag, 1, false}};
    std::vector<int> committed;
    net::steady_timer hold(io, net::steady_timer::time_point::max());
    auto failed = net::co_spawn(io,
        GatedChange(gate, one, runtime, owner, next, committed, 1, &hold), net::use_future);
    io.poll();
    auto waiting = net::co_spawn(io,
        GatedChange(gate, two, runtime, companion, companion_snapshot, committed, 2), net::use_future);
    io.poll();
    hold.cancel();
    io.poll();
    Require(failed.wait_for(std::chrono::seconds::zero()) == std::future_status::ready,
        "the failed transaction must complete while its companion remains blocked");
    bool mutation_failed = false;
    try { failed.get(); }
    catch (const MutationFailure&) { mutation_failed = true; }
    Require(mutation_failed && owner.HasPendingCleanup() && !companion.committed &&
        runtime.resources.find(companion_snapshot->tag) == runtime.resources.end() &&
        owner.committed == old && owner.committed->config_etag == "config-1",
        "failed compensation must retain credentials and block all companion mutations");
    runtime.faults = {{"remove-out:" + old->tag, runtime.counts["remove-out:" + old->tag] + 1}};
    auto retry_failed = net::co_spawn(io, GatedCleanup(gate, one, runtime, owner), net::use_future);
    io.poll();
    Require(retry_failed.wait_for(std::chrono::seconds::zero()) == std::future_status::ready,
        "recovery owner must be admitted ahead of the blocked companion");
    bool cleanup_failed = false;
    try { retry_failed.get(); }
    catch (const MutationFailure&) { cleanup_failed = true; }
    Require(cleanup_failed && owner.HasPendingCleanup() && !companion.committed,
        "a failed recovery attempt must not pass admission to another panel");
    if (close_gate) {
        const auto started = runtime.operations_started;
        gate.Close();
        io.run();
        RequireCancelled(waiting);
        Require(runtime.operations_started == started && owner.HasPendingCleanup() &&
            owner.committed == old && committed.empty(),
            "shutdown must wake blocked panels without starting recovery or dropping retained snapshots");
    } else {
        runtime.faults.clear();
        auto recovered = net::co_spawn(io, GatedCleanup(gate, one, runtime, owner), net::use_future);
        io.run();
        recovered.get();
        waiting.get();
        Require(!owner.HasPendingCleanup() && Empty(runtime, old->tag) &&
            Empty(runtime, next->tag) && Matches(runtime, *companion.committed) &&
            committed == std::vector<int>({2}),
            "only successful owner cleanup may release a waiting companion transaction");
    }
}

}  // namespace

TEST(NodeTransaction, Contract) {
    try {
        TestSuccessAndRefresh();
        TestIncompleteCandidatePreservesLiveService();
        TestFailureMatrix();
        TestRefreshRollbackFailure();
        TestFailedRollbackForcesRebuild();
        TestOrphanCleanupAndBlockedRetry();
        TestCleanupFailureRecovery();
        TestUncommittedCandidateCleanup();
        TestReservationBeforeFirstSuspend();
        TestCancellationRollback(false);
        TestCancellationRollback(true);
        TestRollbackDoesNotDisableFutureStop();
        TestFairMultiPanelTransactions();
        TestCancelledPanelRetainsQueueFairness();
        TestRecoveryOwnershipBlocksCompanions(false);
        TestRecoveryOwnershipBlocksCompanions(true);
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        FAIL() << error.what();
    }
    std::cout << "node transaction fault matrix and recovery passed\n";
}
