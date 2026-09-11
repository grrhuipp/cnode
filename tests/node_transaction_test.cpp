#include "node_transaction.hpp"

#include <asio/co_spawn.hpp>
#include <asio/bind_cancellation_slot.hpp>
#include <asio/cancellation_signal.hpp>
#include <asio/post.hpp>
#include <asio/steady_timer.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/use_future.hpp>

#include <functional>
#include <iostream>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
namespace net = acpp::net;
using namespace acpp::controller;
using acpp::api::NodeInfo;
using acpp::proxyman::inbound::UserSet;

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
    snapshot->rules.resize(version);
    return snapshot;
}

UserSet Users(size_t count) {
    return acpp::proxyman::inbound::PreparedVmessUsers(count);
}

PreparedNodeChange Change(std::shared_ptr<const NodeSnapshot> next, const NodeState& state) {
    PreparedNodeChange change;
    change.users = Users(next->users.size());
    change.next = std::move(next);
    if (state.committed) change.previous_users = Users(state.committed->users.size());
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

    bool Step(std::string operation, const std::function<void()>& mutate) {
        calls.push_back(operation);
        const int occurrence = ++counts[operation];
        const Fault* fault = nullptr;
        for (const auto& candidate : faults) {
            if (candidate.operation == operation && candidate.occurrence == occurrence) fault = &candidate;
        }
        if (fault && !fault->after_mutation) {
            if (fault->return_false) return false;
            throw std::runtime_error(operation + " failed");
        }
        mutate();
        if (fault) {
            if (fault->return_false) return false;
            throw std::runtime_error(operation + " failed");
        }
        return true;
    }

    net::awaitable<void> RemoveInbound(const std::string& tag) {
        co_await net::post(net::use_awaitable);
        Step("remove-in:" + tag, [&] { resources[tag].inbound = false; });
    }
    net::awaitable<void> RemoveOutbound(const std::string& tag) {
        co_await net::post(net::use_awaitable);
        Step("remove-out:" + tag, [&] { resources[tag].outbound = false; });
    }
    net::awaitable<bool> AddInbound(const NodeInfo& config) {
        co_await net::post(net::use_awaitable);
        if (inbound_gate) {
            struct Release {
                Runtime& runtime;
                ~Release() { runtime.gate_released = true; }
            } release{*this};
            gate_entered = true;
            co_await inbound_gate->async_wait(net::use_awaitable);
        }
        const auto tag = Tag(config);
        co_return Step("add-in:" + tag, [&] {
            resources[tag].inbound = true;
            resources[tag].version = config.Path;
        });
    }
    net::awaitable<bool> AddOutbound(const std::string& tag) {
        co_await net::post(net::use_awaitable);
        co_return Step("add-out:" + tag, [&] { resources[tag].outbound = true; });
    }
    net::awaitable<void> UpdateRules(const std::string& tag, const std::vector<acpp::api::DetectRule>& rules) {
        co_await net::post(net::use_awaitable);
        Step("rules:" + tag, [&] { resources[tag].rules = rules.size(); });
    }
    void ApplyUsers(const std::string& tag, const UserSet& users) {
        Step("users:" + tag, [&] {
            resources[tag].users = std::visit([](const auto& values) { return values.size(); }, users);
        });
    }
    void ClearUsers(const std::string& tag, const std::string&) {
        Step("clear-users:" + tag, [&] { resources[tag].users = 0; });
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
    refresh->rules.resize(2);
    Require(!Run(ApplyNodeChange(runtime, state, Change(refresh, state))), "refresh failed");
    Require(state.committed == refresh && state.phase == NodeRuntimePhase::Ready &&
        !state.HasPendingCleanup() && Matches(runtime, *refresh), "refresh must publish the complete new snapshot");
    Require(runtime.counts["add-in:" + first->tag] == 1, "refresh must preserve the existing listener");
    Require(first->users.size() == 1 && first->rules.size() == 1, "published old snapshots must remain immutable");
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
            catch (const std::runtime_error& error) {
                Require(std::string(error.what()) == operation + " failed", "rollback must preserve the original failure");
            }
            Require(state.committed == old && state.phase == NodeRuntimePhase::Ready &&
                !state.HasPendingCleanup() && Matches(runtime, *old) && Empty(runtime, next->tag),
                "every single transition failure must restore the old runtime and remove the candidate");
        }
    }
    for (const auto& operation : {"add-in:" + next->tag, "add-out:" + next->tag}) {
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

void TestRemovalFailureRecovery() {
    Runtime runtime;
    NodeState state;
    const auto old = Snapshot(1000);
    Seed(runtime, state, old);
    runtime.faults = {{"remove-out:" + old->tag, 1, true}};
    Require(static_cast<bool>(Run(RemoveNode(runtime, state))), "partial removal must fail");
    Require(state.committed == old && state.phase == NodeRuntimePhase::RecoveryRequired &&
        state.HasPendingCleanup() && !runtime.resources.at(old->tag).inbound, "partial removal must preserve recovery data");
    runtime.faults.clear();
    Require(!Run(ApplyNodeChange(runtime, state, Change(old, state))) && Matches(runtime, *old),
        "a node that reappears after partial removal must be rebuilt");
    Require(!Run(RemoveNode(runtime, state)) && !state.committed && !state.HasPendingCleanup() &&
        state.phase == NodeRuntimePhase::Stopped && Empty(runtime, old->tag), "complete removal must clear ownership and resources");
}

void TestUncommittedCandidateCleanup() {
    Runtime runtime;
    NodeState state;
    const auto next = Snapshot(2000);
    runtime.faults = {{"add-in:" + next->tag, 1, true}, {"remove-in:" + next->tag, 1, false}};
    Require(static_cast<bool>(Run(ApplyNodeChange(runtime, state, Change(next, state)))) &&
        !state.committed && state.HasPendingCleanup(), "failed initial creation must retain cleanup without a committed node");
    runtime.faults.clear();
    Require(!Run(RemoveNode(runtime, state)) && !state.HasPendingCleanup() && Empty(runtime, next->tag),
        "a missing node must also remove an uncommitted orphan candidate");
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

void TestCancellationKeepsRecoveryState() {
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
    cancellation.emit(net::cancellation_type::terminal);
    io.run();
    Require(completed && failure && runtime.gate_released && state.committed == old &&
        state.phase == NodeRuntimePhase::RecoveryRequired && state.HasPendingCleanup(),
        "cancelled mutation must release the active operation and retain unfinished cleanup");
    Require(state.ReservesPort(1000) && state.ReservesPort(2000),
        "incomplete cleanup must retain endpoint admission reservations");
    try { std::rethrow_exception(failure); }
    catch (const std::system_error& error) {
        Require(error.code() == net::error::operation_aborted, "cancellation must preserve its original cause");
    }
    runtime.inbound_gate = nullptr;
    Require(!Run(ApplyNodeChange(runtime, state, Change(old, state))) && Matches(runtime, *old) &&
        Empty(runtime, next->tag), "a fresh attempt must repair the state left by a cancelled transaction");
    Require(state.ReservesPort(1000) && !state.ReservesPort(2000),
        "completed recovery must release the abandoned candidate endpoint");
    Require(!Run(RemoveNode(runtime, state)) && !state.ReservesPort(1000),
        "completed removal must release the original endpoint");
}
}  // namespace

int main() {
    try {
        TestSuccessAndRefresh();
        TestFailureMatrix();
        TestRefreshRollbackFailure();
        TestFailedRollbackForcesRebuild();
        TestOrphanCleanupAndBlockedRetry();
        TestRemovalFailureRecovery();
        TestUncommittedCandidateCleanup();
        TestReservationBeforeFirstSuspend();
        TestCancellationKeepsRecoveryState();
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
    std::cout << "node transaction fault matrix and recovery passed\n";
    return 0;
}
