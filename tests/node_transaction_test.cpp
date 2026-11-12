#include <gtest/gtest.h>

#include "service/controller/node_transaction.hpp"

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
#include <map>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
namespace net = ::net;
using namespace ::controller;
using ::api::NodeInfo;
using ::proxyman::inbound::UserSet;

std::string Tag(const NodeInfo& config) {
    return config.NodeType + ':' + std::to_string(config.Port);
}

std::shared_ptr<const NodeSnapshot> Snapshot(uint16_t port, size_t version = 1) {
    auto snapshot = std::make_shared<NodeSnapshot>();
    snapshot->config.Port = port;
    snapshot->config.Path = std::to_string(version);
    snapshot->tag = Tag(snapshot->config);
    snapshot->users = std::make_shared<const std::vector<::api::UserInfo>>(version);
    snapshot->users_etag = "users-" + std::to_string(version);
    snapshot->config_etag = "config-" + std::to_string(version);
    snapshot->rules = std::make_shared<const std::vector<::rule::DetectRule>>(version);
    ::transport::internet::StreamSettings stream;
    stream.ws.path = snapshot->config.Path;
    snapshot->inbound = std::make_shared<const ::app::PreparedInbound>(::app::PreparedInbound{
        .binding = {.port = port, .protocol = snapshot->config.NodeType, .tag = snapshot->tag, .listen = {}},
        .receiver = ::proxyman::inbound::MakeReceiverSettings(
            snapshot->tag, {}, snapshot->config.NodeType, std::move(stream), {},
            ::transport::internet::ProxyProtocolMode::Auto, ::routing::RouteWithFallback(snapshot->tag), {}),
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
    auto inbound = std::make_shared<::app::PreparedInbound>(*snapshot.inbound);
    inbound->users = std::make_shared<const UserSet>(
        ::proxyman::inbound::PreparedVmessUsers(count));
    snapshot.inbound = std::move(inbound);
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
    net::awaitable<bool> AddInbound(const ::app::PreparedInbound& inbound) {
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
    net::awaitable<void> UpdateRules(
        const std::string& tag,
        std::shared_ptr<const std::vector<::rule::DetectRule>> rules) {
        ++operations_started;
        co_await net::post(net::use_awaitable);
        Step("rules:" + tag, [&] { resources[tag].rules = rules ? rules->size() : 0; });
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

std::exception_ptr RunNodeRuntimeOperation(net::awaitable<void> task) {
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
        true, true, snapshot->users ? snapshot->users->size() : 0, snapshot->rules ? snapshot->rules->size() : 0, snapshot->config.Path};
}

void ExpectMatches(const Runtime& runtime, const NodeSnapshot& snapshot) {
    const auto it = runtime.resources.find(snapshot.tag);
    ASSERT_NE(it, runtime.resources.end()) << snapshot.tag;
    const auto& actual = it->second;
    EXPECT_TRUE(actual.inbound);
    EXPECT_TRUE(actual.outbound);
    EXPECT_EQ(actual.users, snapshot.users ? snapshot.users->size() : 0);
    EXPECT_EQ(actual.rules, snapshot.rules ? snapshot.rules->size() : 0);
    EXPECT_EQ(actual.version, snapshot.config.Path);
}

void ExpectEmpty(const Runtime& runtime, const std::string& tag) {
    const auto it = runtime.resources.find(tag);
    if (it == runtime.resources.end()) return;
    EXPECT_FALSE(it->second.inbound) << tag;
    EXPECT_FALSE(it->second.outbound) << tag;
    EXPECT_EQ(it->second.users, 0u) << tag;
    EXPECT_EQ(it->second.rules, 0u) << tag;
}

TEST(NodeTransaction, CreatesCompleteRuntime) {
    Runtime runtime;
    NodeState state;
    const auto first = Snapshot(1000);
    ASSERT_FALSE(RunNodeRuntimeOperation(ApplyNodeChange(runtime, state, first)));
    EXPECT_EQ(state.committed, first);
    EXPECT_EQ(state.phase, NodeRuntimePhase::Ready);
    EXPECT_FALSE(state.HasPendingCleanup());
    ExpectMatches(runtime, *first);
}

TEST(NodeTransaction, RefreshPublishesUsersAndRulesWithoutReplacingListener) {
    Runtime runtime;
    NodeState state;
    const auto first = Snapshot(1000);
    Seed(runtime, state, first);
    auto refresh = std::make_shared<NodeSnapshot>(*first);
    refresh->users = std::make_shared<const std::vector<::api::UserInfo>>(2);
    ReplaceUsers(*refresh, 2);
    refresh->users_etag = "users-2";
    refresh->rules = std::make_shared<const std::vector<::rule::DetectRule>>(2);
    ASSERT_FALSE(RunNodeRuntimeOperation(ApplyNodeChange(runtime, state, refresh)));
    EXPECT_EQ(state.committed, refresh);
    EXPECT_EQ(state.phase, NodeRuntimePhase::Ready);
    EXPECT_FALSE(state.HasPendingCleanup());
    ExpectMatches(runtime, *refresh);
    EXPECT_EQ(runtime.counts["add-in:" + first->tag], 0);
    EXPECT_EQ(first->users->size(), 1u);
    EXPECT_EQ(first->rules->size(), 1u);
    EXPECT_EQ(state.committed->users_etag, "users-2");
    EXPECT_EQ(first->users_etag, "users-1");
}

enum class RefreshPayload { Users, Rules, Validators };

struct RefreshCase {
    const char* name;
    RefreshPayload payload;
    size_t count;
    bool fail_after_mutation;
};

class SelectiveNodeRefresh : public testing::TestWithParam<RefreshCase> {};

TEST_P(SelectiveNodeRefresh, RetainsUnchangedResourcesAndCommitsOnlyOnSuccess) {
    const auto& test = GetParam();
    Runtime runtime;
    NodeState state;
    const auto old = Snapshot(1000);
    Seed(runtime, state, old);
    auto next = std::make_shared<NodeSnapshot>(*old);
    if (test.payload == RefreshPayload::Users) {
        next->users = std::make_shared<const std::vector<::api::UserInfo>>(test.count);
        ReplaceUsers(*next, test.count);
        next->users_etag = "users-2";
    } else {
        next->config_etag = "config-2";
    }
    if (test.payload == RefreshPayload::Rules) {
        next->rules = std::make_shared<const std::vector<::rule::DetectRule>>(test.count);
    }
    // Unchanged resources must remain usable even when their update path fails.
    if (test.payload != RefreshPayload::Users) {
        runtime.faults.push_back({"users:" + old->tag});
    }
    if (test.payload != RefreshPayload::Rules) {
        runtime.faults.push_back({"rules:" + old->tag});
    }
    if (test.fail_after_mutation) {
        const auto operation = test.payload == RefreshPayload::Users ? "users:" : "rules:";
        runtime.faults.push_back({operation + old->tag, 1, true});
    }

    const auto failure = RunNodeRuntimeOperation(ApplyNodeChange(runtime, state, next));
    EXPECT_EQ(static_cast<bool>(failure), test.fail_after_mutation);
    EXPECT_EQ(state.phase, NodeRuntimePhase::Ready);
    EXPECT_FALSE(state.HasPendingCleanup());
    if (test.fail_after_mutation) {
        EXPECT_EQ(state.committed, old);
        ExpectMatches(runtime, *old);
    } else {
        EXPECT_EQ(state.committed, next);
        ExpectMatches(runtime, *next);
    }
}

INSTANTIATE_TEST_SUITE_P(PayloadBoundaries, SelectiveNodeRefresh, testing::Values(
    RefreshCase{"UsersChanged", RefreshPayload::Users, 2, false},
    RefreshCase{"UsersCleared", RefreshPayload::Users, 0, false},
    RefreshCase{"RulesChanged", RefreshPayload::Rules, 2, false},
    RefreshCase{"RulesCleared", RefreshPayload::Rules, 0, false},
    RefreshCase{"ValidatorsOnly", RefreshPayload::Validators, 1, false},
    RefreshCase{"UsersMutationFailure", RefreshPayload::Users, 2, true},
    RefreshCase{"RulesMutationFailure", RefreshPayload::Rules, 2, true}),
    [](const testing::TestParamInfo<RefreshCase>& info) { return info.param.name; });

struct TransitionFault {
    const char* name;
    const char* operation;
    bool candidate;
    bool after_mutation;
    bool return_false;
};

class NodeTransitionFailure : public ::testing::TestWithParam<TransitionFault> {};

TEST_P(NodeTransitionFailure, RestoresCommittedRuntimeAndValidators) {
    Runtime runtime;
    NodeState state;
    const auto old = Snapshot(1000);
    const auto next = Snapshot(2000, 2);
    Seed(runtime, state, old);
    const auto& fault = GetParam();
    const auto operation = std::string(fault.operation) + (fault.candidate ? next->tag : old->tag);
    runtime.faults.push_back({operation, 1, fault.after_mutation, fault.return_false});
    const auto failure = RunNodeRuntimeOperation(ApplyNodeChange(runtime, state, next));
    EXPECT_TRUE(failure);
    if (failure && !fault.return_false) {
        try {
            std::rethrow_exception(failure);
        } catch (const MutationFailure& error) {
            EXPECT_EQ(error.operation, operation);
        } catch (...) {
            ADD_FAILURE() << "change did not preserve the original mutation failure";
        }
    }
    EXPECT_EQ(state.committed, old);
    EXPECT_EQ(state.phase, NodeRuntimePhase::Ready);
    EXPECT_FALSE(state.HasPendingCleanup());
    ExpectMatches(runtime, *old);
    ExpectEmpty(runtime, next->tag);
    ASSERT_TRUE(state.committed);
    EXPECT_EQ(state.committed->users_etag, "users-1");
    EXPECT_EQ(state.committed->config_etag, "config-1");
}

INSTANTIATE_TEST_SUITE_P(MutationFaults, NodeTransitionFailure, ::testing::Values(
    TransitionFault{"UsersBefore", "users:", true, false, false},
    TransitionFault{"UsersAfter", "users:", true, true, false},
    TransitionFault{"AddOutboundBefore", "add-out:", true, false, false},
    TransitionFault{"AddOutboundAfter", "add-out:", true, true, false},
    TransitionFault{"AddInboundBefore", "add-in:", true, false, false},
    TransitionFault{"AddInboundAfter", "add-in:", true, true, false},
    TransitionFault{"RemoveInboundBefore", "remove-in:", false, false, false},
    TransitionFault{"RemoveInboundAfter", "remove-in:", false, true, false},
    TransitionFault{"RemoveOutboundBefore", "remove-out:", false, false, false},
    TransitionFault{"RemoveOutboundAfter", "remove-out:", false, true, false},
    TransitionFault{"ClearUsersBefore", "clear-users:", false, false, false},
    TransitionFault{"ClearUsersAfter", "clear-users:", false, true, false},
    TransitionFault{"ClearRulesBefore", "rules:", false, false, false},
    TransitionFault{"ClearRulesAfter", "rules:", false, true, false},
    TransitionFault{"PublishRulesBefore", "rules:", true, false, false},
    TransitionFault{"PublishRulesAfter", "rules:", true, true, false},
    TransitionFault{"AddInboundFalseBefore", "add-in:", true, false, true},
    TransitionFault{"AddInboundFalseAfter", "add-in:", true, true, true}),
    [](const ::testing::TestParamInfo<TransitionFault>& info) { return info.param.name; });

TEST(NodeTransaction, FailedRefreshCompensationForcesRebuild) {
    Runtime runtime;
    NodeState state;
    const auto old = Snapshot(1000);
    auto next = std::make_shared<NodeSnapshot>(*old);
    next->users = std::make_shared<const std::vector<::api::UserInfo>>(2);
    ReplaceUsers(*next, 2);
    next->rules = std::make_shared<const std::vector<::rule::DetectRule>>(2);
    Seed(runtime, state, old);
    runtime.faults = {{"users:" + old->tag, 1, true}, {"rules:" + old->tag, 2, false}};
    EXPECT_TRUE(RunNodeRuntimeOperation(ApplyNodeChange(runtime, state, next)));
    EXPECT_EQ(state.committed, old);
    EXPECT_EQ(state.phase, NodeRuntimePhase::RecoveryRequired);
    EXPECT_EQ(runtime.resources.at(old->tag).rules, 2u);
    runtime.faults.clear();
    ASSERT_FALSE(RunNodeRuntimeOperation(ApplyNodeChange(runtime, state, old)));
    ExpectMatches(runtime, *old);
    EXPECT_EQ(runtime.counts["add-in:" + old->tag], 1);
}

TEST(NodeTransaction, FailedRollbackRebuildsEvenIdenticalConfig) {
    Runtime runtime;
    NodeState state;
    const auto old = Snapshot(1000);
    const auto next = Snapshot(1000, 2);
    Seed(runtime, state, old);
    runtime.faults = {{"rules:" + old->tag, 1, true}, {"add-in:" + old->tag, 2, false}};
    EXPECT_TRUE(RunNodeRuntimeOperation(ApplyNodeChange(runtime, state, next)));
    EXPECT_EQ(state.committed, old);
    EXPECT_EQ(state.phase, NodeRuntimePhase::RecoveryRequired);
    EXPECT_TRUE(state.HasPendingCleanup());
    EXPECT_FALSE(runtime.resources.at(old->tag).inbound);
    const auto installs = runtime.counts["add-in:" + old->tag];
    runtime.faults.clear();
    ASSERT_FALSE(RunNodeRuntimeOperation(ApplyNodeChange(runtime, state, old)));
    EXPECT_GT(runtime.counts["add-in:" + old->tag], installs);
    ExpectMatches(runtime, *old);
    EXPECT_EQ(state.phase, NodeRuntimePhase::Ready);
    EXPECT_FALSE(state.HasPendingCleanup());
}

TEST(NodeTransaction, OrphanCleanupBlocksCandidatesUntilRecovery) {
    Runtime runtime;
    NodeState state;
    const auto old = Snapshot(1000);
    const auto next = Snapshot(2000, 2);
    const auto later = Snapshot(3000, 3);
    Seed(runtime, state, old);
    runtime.faults = {{"add-in:" + next->tag, 1, true}, {"remove-in:" + next->tag, 1, false}};
    EXPECT_TRUE(RunNodeRuntimeOperation(ApplyNodeChange(runtime, state, next)));
    EXPECT_TRUE(runtime.resources.at(next->tag).inbound);
    EXPECT_TRUE(state.HasPendingCleanup());
    runtime.faults = {{"remove-out:" + old->tag, runtime.counts["remove-out:" + old->tag] + 1, true}};
    EXPECT_TRUE(RunNodeRuntimeOperation(ApplyNodeChange(runtime, state, later)));
    ExpectEmpty(runtime, later->tag);
    EXPECT_EQ(state.committed, old);
    EXPECT_TRUE(state.HasPendingCleanup());
    runtime.faults.clear();
    ASSERT_FALSE(RunNodeRuntimeOperation(ApplyNodeChange(runtime, state, later)));
    ExpectEmpty(runtime, old->tag);
    ExpectEmpty(runtime, next->tag);
    ExpectMatches(runtime, *later);
    EXPECT_EQ(state.committed, later);
    EXPECT_FALSE(state.HasPendingCleanup());
}

TEST(NodeTransaction, PartialCleanupRetainsSnapshotForRecovery) {
    Runtime runtime;
    NodeState state;
    const auto old = Snapshot(1000);
    Seed(runtime, state, old);
    state.pending_cleanup = {old, {}};
    runtime.faults = {{"remove-out:" + old->tag, 1, true}};
    EXPECT_TRUE(RunNodeRuntimeOperation(CleanPendingNodeRuntime(runtime, state)));
    EXPECT_EQ(state.committed, old);
    EXPECT_EQ(state.phase, NodeRuntimePhase::RecoveryRequired);
    EXPECT_TRUE(state.HasPendingCleanup());
    EXPECT_FALSE(runtime.resources.at(old->tag).inbound);
    runtime.faults.clear();
    ASSERT_FALSE(RunNodeRuntimeOperation(ApplyNodeChange(runtime, state, old)));
    ExpectMatches(runtime, *old);
    ASSERT_TRUE(state.committed);
    EXPECT_EQ(state.committed->users_etag, "users-1");
}

TEST(NodeTransaction, CleansUncommittedOrphanCandidate) {
    Runtime runtime;
    NodeState state;
    const auto next = Snapshot(2000);
    runtime.faults = {{"add-in:" + next->tag, 1, true}, {"remove-in:" + next->tag, 1, false}};
    EXPECT_TRUE(RunNodeRuntimeOperation(ApplyNodeChange(runtime, state, next)));
    EXPECT_FALSE(state.committed);
    EXPECT_TRUE(state.HasPendingCleanup());
    runtime.faults.clear();
    EXPECT_FALSE(RunNodeRuntimeOperation(CleanPendingNodeRuntime(runtime, state)));
    EXPECT_FALSE(state.HasPendingCleanup());
    ExpectEmpty(runtime, next->tag);
}

TEST(NodeTransaction, ReservesEndpointsBeforeFirstSuspend) {
    Runtime runtime;
    NodeState state;
    const auto old = Snapshot(1000);
    const auto next = Snapshot(2000);
    Seed(runtime, state, old);
    net::io_context io;
    auto completed = net::co_spawn(io, ApplyNodeChange(runtime, state, next), net::use_future);
    EXPECT_EQ(io.poll_one(), 1u);
    EXPECT_EQ(state.phase, NodeRuntimePhase::Updating);
    EXPECT_TRUE(state.ReservesPort(1000));
    EXPECT_TRUE(state.ReservesPort(2000));
    io.run();
    EXPECT_NO_THROW(completed.get());
    EXPECT_FALSE(state.ReservesPort(1000));
    EXPECT_TRUE(state.ReservesPort(2000));
    EXPECT_FALSE(RunNodeRuntimeOperation(CleanPendingNodeRuntime(runtime, state)));
    state.phase = NodeRuntimePhase::Stopped;
    EXPECT_FALSE(state.ReservesPort(2000));
}

class NodeCancellation : public ::testing::TestWithParam<bool> {};

TEST_P(NodeCancellation, JoinsMutationAndRecoversCommittedRuntime) {
    const bool close_runtime = GetParam();
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
    net::co_spawn(io, ApplyNodeChange(runtime, state, next),
        net::bind_cancellation_slot(cancellation.slot(), [&](std::exception_ptr error) {
            completed = true;
            failure = error;
        }));
    io.poll();
    EXPECT_TRUE(runtime.gate_entered);
    EXPECT_FALSE(completed);
    EXPECT_TRUE(state.ReservesPort(1000));
    EXPECT_TRUE(state.ReservesPort(2000));
    const auto started_before_stop = runtime.operations_started;
    cancellation.emit(net::cancellation_type::terminal);
    runtime.closed = close_runtime;
    io.poll();
    const bool cancellation_joined = completed;
    if (!completed) {
        gate.cancel();
        io.restart();
        io.run();
    }
    EXPECT_TRUE(cancellation_joined);
    EXPECT_TRUE(completed);
    EXPECT_TRUE(runtime.gate_released);
    EXPECT_EQ(state.committed, old);
    if (close_runtime) {
        EXPECT_EQ(state.phase, NodeRuntimePhase::RecoveryRequired);
        EXPECT_TRUE(state.HasPendingCleanup());
        EXPECT_TRUE(state.ReservesPort(1000));
        EXPECT_TRUE(state.ReservesPort(2000));
        EXPECT_EQ(runtime.operations_started, started_before_stop);
    } else {
        EXPECT_EQ(state.phase, NodeRuntimePhase::Ready);
        EXPECT_FALSE(state.HasPendingCleanup());
        ExpectMatches(runtime, *old);
        ExpectEmpty(runtime, next->tag);
        EXPECT_FALSE(state.ReservesPort(2000));
    }
    EXPECT_TRUE(failure);
    if (failure) {
        try { std::rethrow_exception(failure); }
        catch (const std::system_error& error) {
            EXPECT_EQ(error.code(), net::error::operation_aborted);
        } catch (...) { ADD_FAILURE() << "cancellation lost its original cause"; }
    }
    runtime.inbound_gate = nullptr;
    runtime.closed = false;
    EXPECT_FALSE(RunNodeRuntimeOperation(ApplyNodeChange(runtime, state, old)));
    ExpectMatches(runtime, *old);
    ExpectEmpty(runtime, next->tag);
    EXPECT_TRUE(state.ReservesPort(1000));
    EXPECT_FALSE(state.ReservesPort(2000));
    state.pending_cleanup = {old, {}};
    EXPECT_FALSE(RunNodeRuntimeOperation(CleanPendingNodeRuntime(runtime, state)));
    EXPECT_FALSE(state.ReservesPort(1000));
}

INSTANTIATE_TEST_SUITE_P(RuntimeAdmission, NodeCancellation, ::testing::Bool(),
    [](const ::testing::TestParamInfo<bool>& info) {
        return info.param ? "Closed" : "Open";
    });

net::awaitable<void> RecoverThenWait(Runtime& runtime, NodeState& state,
                                   std::shared_ptr<const NodeSnapshot> next, net::steady_timer& wait,
                                   bool& recovered) {
    bool failed = false;
    try {
        co_await ApplyNodeChange(runtime, state, std::move(next));
    } catch (const MutationFailure&) {
        failed = true;
    }
    EXPECT_TRUE(failed);
    EXPECT_EQ(state.phase, NodeRuntimePhase::Ready);
    recovered = true;
    co_await wait.async_wait(net::use_awaitable);
}

TEST(NodeTransaction, RollbackDoesNotDisableFutureStop) {
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
    net::co_spawn(io, RecoverThenWait(runtime, state, next, wait, recovered),
        net::bind_cancellation_slot(stop.slot(), [&](std::exception_ptr error) {
            completed = true;
            failure = error;
        }));
    io.poll();
    EXPECT_TRUE(recovered);
    EXPECT_FALSE(completed);
    stop.emit(net::cancellation_type::terminal);
    io.poll();
    const bool stopped = completed;
    if (!stopped) {
        wait.cancel();
        io.restart();
        io.run();
    }
    EXPECT_TRUE(stopped);
    ASSERT_TRUE(failure);
    try { std::rethrow_exception(failure); }
    catch (const std::system_error& error) {
        EXPECT_EQ(error.code(), net::error::operation_aborted);
    } catch (...) { ADD_FAILURE() << "later stop lost cancellation semantics"; }
}

TEST(NodeTransaction, IncompleteCandidatePreservesLiveService) {
    Runtime runtime;
    NodeState state;
    const auto old = Snapshot(1000);
    Seed(runtime, state, old);
    auto next = std::make_shared<NodeSnapshot>(*Snapshot(1000, 2));
    next->inbound.reset();
    EXPECT_TRUE(RunNodeRuntimeOperation(ApplyNodeChange(runtime, state, next)));
    EXPECT_TRUE(runtime.calls.empty());
    EXPECT_EQ(state.committed, old);
    EXPECT_EQ(state.phase, NodeRuntimePhase::Ready);
    ExpectMatches(runtime, *old);
}

net::awaitable<void> GatedChange(
    NodeMutationGate& gate, NodeMutationGate::Participant& participant,
    Runtime& runtime, NodeState& state, std::shared_ptr<const NodeSnapshot> next,
    std::vector<int>& committed, int panel, net::steady_timer* hold = nullptr) {
    auto lease = co_await gate.Acquire(participant);
    if (hold) {
        (void)co_await hold->async_wait(net::as_tuple(net::use_awaitable));
    }
    co_await ApplyNodeChange(runtime, state, std::move(next));
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

void ExpectCancelled(std::future<void>& result) {
    EXPECT_THROW({
        try { result.get(); }
        catch (const std::system_error& error) {
            EXPECT_EQ(error.code(), net::error::operation_aborted);
            throw;
        }
    }, std::system_error);
}

void JoinGatedChanges(net::io_context& io, NodeMutationGate& gate) {
    io.restart();
    io.poll();
    // Drain normally first, then join any admission stranded by a failed change.
    gate.Close();
    io.restart();
    io.run();
}

TEST(NodeTransaction, WaitingPanelsCommitInFairOrder) {
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
    EXPECT_TRUE(runtime.calls.empty());
    EXPECT_FALSE(first.committed);
    EXPECT_FALSE(second.committed);
    EXPECT_FALSE(third.committed);
    hold.cancel();
    JoinGatedChanges(io, gate);
    EXPECT_NO_THROW(first_done.get());
    EXPECT_NO_THROW(second_done.get());
    EXPECT_NO_THROW(third_done.get());
    EXPECT_EQ(committed, std::vector<int>({1, 2, 3, 1}));
    ASSERT_TRUE(first.committed);
    ASSERT_TRUE(second.committed);
    ASSERT_TRUE(third.committed);
    ExpectMatches(runtime, *first.committed);
    ExpectMatches(runtime, *second.committed);
    ExpectMatches(runtime, *third.committed);
    EXPECT_EQ(first.committed->config_etag, "config-2");
}

TEST(NodeTransaction, RejectsDuplicatePendingAdmission) {
    net::io_context io;
    NodeMutationGate gate;
    NodeState first, second;
    NodeMutationGate::Participant one(gate, io.get_executor(), first);
    NodeMutationGate::Participant two(gate, io.get_executor(), second);
    gate.Seal();
    Runtime runtime;
    std::vector<int> committed;
    net::steady_timer hold(io, net::steady_timer::time_point::max());
    auto first_done = net::co_spawn(io,
        GatedChange(gate, one, runtime, first, Snapshot(1000), committed, 1, &hold), net::use_future);
    io.poll();
    auto second_done = net::co_spawn(io,
        GatedChange(gate, two, runtime, second, Snapshot(2000), committed, 2), net::use_future);
    auto duplicate = net::co_spawn(io,
        GatedChange(gate, two, runtime, second, Snapshot(4000), committed, 4), net::use_future);
    io.poll();
    EXPECT_EQ(duplicate.wait_for(std::chrono::seconds::zero()), std::future_status::ready);
    hold.cancel();
    JoinGatedChanges(io, gate);
    EXPECT_THROW(duplicate.get(), std::logic_error);
    EXPECT_NO_THROW(first_done.get());
    EXPECT_NO_THROW(second_done.get());
}

TEST(NodeTransaction, CancelledPanelRejoinsBehindExistingWaiters) {
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
    EXPECT_EQ(cancelled.wait_for(std::chrono::seconds::zero()), std::future_status::ready);
    auto retried = net::co_spawn(io,
        GatedChange(gate, two, runtime, second, Snapshot(2000), committed, 2), net::use_future);
    io.poll();
    hold.cancel();
    JoinGatedChanges(io, gate);
    ExpectCancelled(cancelled);
    EXPECT_NO_THROW(first_done.get());
    EXPECT_NO_THROW(third_done.get());
    EXPECT_NO_THROW(retried.get());
    EXPECT_EQ(committed, std::vector<int>({1, 3, 2}));
}

class NodeRecoveryOwnership : public ::testing::TestWithParam<bool> {};

TEST_P(NodeRecoveryOwnership, BlocksCompanionsUntilCleanupOrShutdown) {
    const bool close_gate = GetParam();
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
    const bool failure_ready = failed.wait_for(std::chrono::seconds::zero()) == std::future_status::ready;
    EXPECT_TRUE(failure_ready);
    if (!failure_ready) {
        gate.Close();
        io.restart();
        io.run();
        EXPECT_THROW(failed.get(), std::exception);
        EXPECT_THROW(waiting.get(), std::exception);
        return;
    }
    EXPECT_THROW(failed.get(), MutationFailure);
    EXPECT_TRUE(owner.HasPendingCleanup());
    EXPECT_FALSE(companion.committed);
    EXPECT_EQ(runtime.resources.find(companion_snapshot->tag), runtime.resources.end());
    EXPECT_EQ(owner.committed, old);
    if (owner.committed) EXPECT_EQ(owner.committed->config_etag, "config-1");
    runtime.faults = {{"remove-out:" + old->tag, runtime.counts["remove-out:" + old->tag] + 1}};
    auto retry_failed = net::co_spawn(io, GatedCleanup(gate, one, runtime, owner), net::use_future);
    io.poll();
    const bool retry_ready = retry_failed.wait_for(std::chrono::seconds::zero()) == std::future_status::ready;
    EXPECT_TRUE(retry_ready);
    if (!retry_ready) {
        gate.Close();
        io.restart();
        io.run();
        EXPECT_THROW(retry_failed.get(), std::exception);
        EXPECT_THROW(waiting.get(), std::exception);
        return;
    }
    EXPECT_THROW(retry_failed.get(), MutationFailure);
    EXPECT_TRUE(owner.HasPendingCleanup());
    EXPECT_FALSE(companion.committed);
    if (close_gate) {
        const auto started = runtime.operations_started;
        gate.Close();
        io.run();
        ExpectCancelled(waiting);
        EXPECT_EQ(runtime.operations_started, started);
        EXPECT_TRUE(owner.HasPendingCleanup());
        EXPECT_EQ(owner.committed, old);
        EXPECT_TRUE(committed.empty());
    } else {
        runtime.faults.clear();
        auto recovered = net::co_spawn(io, GatedCleanup(gate, one, runtime, owner), net::use_future);
        JoinGatedChanges(io, gate);
        EXPECT_NO_THROW(recovered.get());
        EXPECT_NO_THROW(waiting.get());
        EXPECT_FALSE(owner.HasPendingCleanup());
        ExpectEmpty(runtime, old->tag);
        ExpectEmpty(runtime, next->tag);
        ASSERT_TRUE(companion.committed);
        ExpectMatches(runtime, *companion.committed);
        EXPECT_EQ(committed, std::vector<int>({2}));
    }
}

INSTANTIATE_TEST_SUITE_P(RecoveryCompletion, NodeRecoveryOwnership, ::testing::Bool(),
    [](const ::testing::TestParamInfo<bool>& info) {
        return info.param ? "Shutdown" : "Cleanup";
    });

}  // namespace

