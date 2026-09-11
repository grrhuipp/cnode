#pragma once

#include "node_state.hpp"
#include "node_transition.hpp"

#include <exception>
#include <stdexcept>
#include <utility>

namespace acpp::controller {

// Operations are supplied by NodeRuntime in production. Its completion boundary
// includes all started Worker mutations, even when an operation throws.
template <typename Runtime>
net::awaitable<void> CleanPendingNodeRuntime(Runtime& runtime, NodeState& state) {
    if (!state.HasPendingCleanup()) co_return;
    state.phase = NodeRuntimePhase::RecoveryRequired;
    for (size_t i = 0; i < state.pending_cleanup.size(); ++i) {
        const auto& target = state.pending_cleanup[i];
        if (!target || (i != 0 && state.pending_cleanup[0] &&
                       target->tag == state.pending_cleanup[0]->tag)) continue;
        co_await runtime.RemoveInbound(target->tag);
        co_await runtime.RemoveOutbound(target->tag);
        runtime.ClearUsers(target->tag, target->protocol);
        co_await runtime.UpdateRules(target->tag, {});
    }
    // Retain every target until the complete cleanup succeeds. Repeating a
    // completed removal is safe; forgetting an unfinished candidate is not.
    state.pending_cleanup = {};
    state.phase = NodeRuntimePhase::Stopped;
}

template <typename Runtime>
net::awaitable<void> RemoveNode(Runtime& runtime, NodeState& state) {
    if (!state.HasPendingCleanup() && state.phase != NodeRuntimePhase::Stopped) {
        state.pending_cleanup = {state.committed, {}};
    }
    co_await CleanPendingNodeRuntime(runtime, state);
    state.committed.reset();
    state.phase = NodeRuntimePhase::Stopped;
}

template <typename Runtime>
net::awaitable<void> ApplyNodeChange(
    Runtime& runtime, NodeState& state, PreparedNodeChange change) {
    const auto old = state.committed;
    const auto& next = change.next;
    if (!next) throw std::logic_error("node change requires a prepared snapshot");
    const auto plan = PlanNodeTransition(old ? &old->config : nullptr,
        state.phase == NodeRuntimePhase::Ready, next->config);
    if ((plan.Transitioning() && (!change.replace_users || !change.replace_rules)) ||
        (old && (plan.Transitioning() || change.replace_users) && !change.previous_users)) {
        throw std::logic_error("node change requires complete prepared user snapshots");
    }

    co_await CleanPendingNodeRuntime(runtime, state);
    const bool recovering_old = old && state.phase != NodeRuntimePhase::Ready;
    const auto& tag = next->tag;
    const std::string empty_tag;
    const auto& old_tag = old ? old->tag : empty_tag;
    const bool different_tag = old_tag != tag;

    // These shared snapshots are already allocated. Recording cleanup and
    // publishing success cannot introduce an allocation failure after effects.
    state.pending_cleanup = {old, next};
    state.phase = NodeRuntimePhase::Updating;
    struct IncompleteOnExit {
        NodeState& state;
        ~IncompleteOnExit() {
            if (state.phase == NodeRuntimePhase::Updating) {
                state.phase = NodeRuntimePhase::RecoveryRequired;
            }
        }
    } incomplete{state};

    bool users_attempted = false;
    bool rules_attempted = false;
    bool outbound_attempted = false;
    bool inbound_attempted = false;
    bool old_inbound_retired = recovering_old;
    bool old_outbound_retired = recovering_old;
    bool old_users_cleared = recovering_old;
    bool old_rules_retired = recovering_old;
    std::exception_ptr failure;
    try {
        if (!plan.Transitioning()) {
            if (change.replace_rules) {
                rules_attempted = true;
                co_await runtime.UpdateRules(tag, next->rules);
            }
            if (change.replace_users) {
                users_attempted = true;
                runtime.ApplyUsers(tag, change.users);
            }
        } else {
            if (plan.DestructiveSwap()) {
                old_inbound_retired = true;
                co_await runtime.RemoveInbound(old_tag);
            }
            users_attempted = true;
            runtime.ApplyUsers(tag, change.users);
            outbound_attempted = true;
            if (!co_await runtime.AddOutbound(tag)) {
                throw std::runtime_error("candidate outbound creation failed");
            }
            inbound_attempted = true;
            if (!co_await runtime.AddInbound(next->config)) {
                throw std::runtime_error("candidate inbound creation failed");
            }
            if (old && different_tag) {
                if (plan.RetireOldInboundBeforeCommit()) {
                    old_inbound_retired = true;
                    co_await runtime.RemoveInbound(old_tag);
                }
                old_outbound_retired = true;
                co_await runtime.RemoveOutbound(old_tag);
                old_users_cleared = true;
                runtime.ClearUsers(old_tag, old->protocol);
                old_rules_retired = true;
                co_await runtime.UpdateRules(old_tag, {});
            }
            rules_attempted = true;
            co_await runtime.UpdateRules(tag, next->rules);
        }
        state.committed = next;
        state.pending_cleanup = {};
        state.phase = NodeRuntimePhase::Ready;
        co_return;
    } catch (...) {
        failure = std::current_exception();
    }

    bool restored = true;
    if (plan.Transitioning()) {
        if (inbound_attempted) {
            try { co_await runtime.RemoveInbound(tag); }
            catch (...) { restored = false; }
        }
        if (rules_attempted && different_tag) {
            try { co_await runtime.UpdateRules(tag, {}); }
            catch (...) { restored = false; }
        }
        if (outbound_attempted && different_tag) {
            try { co_await runtime.RemoveOutbound(tag); }
            catch (...) { restored = false; }
        }
        if (users_attempted && different_tag) {
            try { runtime.ClearUsers(tag, next->protocol); }
            catch (...) { restored = false; }
        }
    }
    if (old) {
        if ((!different_tag && users_attempted) || old_users_cleared) {
            try { runtime.ApplyUsers(old_tag, *change.previous_users); }
            catch (...) { restored = false; }
        }
        if ((!different_tag && outbound_attempted) || old_outbound_retired) {
            try {
                if (!co_await runtime.AddOutbound(old_tag)) restored = false;
            } catch (...) { restored = false; }
        }
        if ((!different_tag && rules_attempted) || old_rules_retired) {
            try { co_await runtime.UpdateRules(old_tag, old->rules); }
            catch (...) { restored = false; }
        }
        if ((!different_tag && inbound_attempted) || old_inbound_retired) {
            try {
                if (!co_await runtime.AddInbound(old->config)) restored = false;
            } catch (...) { restored = false; }
        }
    }
    if (restored) {
        state.pending_cleanup = {};
        state.phase = old ? NodeRuntimePhase::Ready : NodeRuntimePhase::Stopped;
    }
    std::rethrow_exception(failure);
}

}  // namespace acpp::controller
