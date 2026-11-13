#pragma once

#include "api/api.hpp"
#include "app/prepared_inbound.hpp"
#include "app/proxyman/outbound_handler.hpp"
#include "app/stats.hpp"
#include "common/user_online_tracker.hpp"
#include "common/constants.hpp"
#include "infra/config_types.hpp"
#include "infra/config.hpp"

#include <asio/as_tuple.hpp>
#include <asio/steady_timer.hpp>
#include <asio/this_coro.hpp>
#include <asio/use_awaitable.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>
namespace controller {
[[nodiscard]] inline bool ShouldEnableInboundTls(
    const infra::PanelConfig& panel_config,
    const api::NodeInfo& node_config) noexcept {
    if (!panel_config.TLSEnable) {
        return false;
    }

    // These protocols always terminate TLS; the panel switch declares that
    // this cnode instance owns a usable certificate.
    return node_config.EnableTLS ||
        app::RegisteredProtocolTraits(node_config.NodeType).requires_tls;
}

// Panel configuration mapping: node and user records to the source-neutral
// InboundSpec consumed by the shared inbound builder. Throws
// std::invalid_argument when the node's stream settings are unsupported.
[[nodiscard]] infra::InboundSpec MapPanelInbound(
    const infra::PanelConfig& panel_config,
    const api::NodeInfo& node_config,
    std::span<const api::UserInfo> users);

[[nodiscard]] std::vector<infra::InboundUserSpec> MapPanelUsers(
    const api::NodeInfo& node_config,
    std::span<const api::UserInfo> users);


// Constructed before runtime mutations and immutable after publication.
// Refresh candidates retain the shared identity of unchanged payloads.
struct NodeSnapshot {
    api::NodeInfo config;
    std::shared_ptr<const std::vector<api::UserInfo>> users;
    std::string users_etag;
    std::string config_etag;
    std::shared_ptr<const std::vector<common::DetectRule>> rules;
    std::string tag;
    // Prepared by the shared inbound builder; carries the prepared users.
    std::shared_ptr<const app::PreparedInbound> inbound;
    std::shared_ptr<const app::PreparedOutboundConfig> outbound;
};

enum class NodeRuntimePhase { Stopped, Ready, Updating, RecoveryRequired };

struct NodeState {
    std::shared_ptr<const NodeSnapshot> committed;
    NodeRuntimePhase phase = NodeRuntimePhase::Stopped;
    // A failed transition can leave only its old and candidate tags behind.
    // No new transition starts until both have been cleaned successfully.
    std::array<std::shared_ptr<const NodeSnapshot>, 2> pending_cleanup;
    std::optional<app::UserPublicationRollback> user_recovery;

    [[nodiscard]] bool HasPendingCleanup() const noexcept {
        return pending_cleanup[0] || pending_cleanup[1] || user_recovery.has_value();
    }

    // Controller-executor admission uses the same snapshots as recovery.
    // Keep both endpoints reserved until every old/candidate Worker effect is
    // joined and either committed, compensated or cleaned.
    [[nodiscard]] bool ReservesPort(uint16_t port) const noexcept {
        if (phase != NodeRuntimePhase::Stopped && committed && committed->config.Port == port) {
            return true;
        }
        for (const auto& target : pending_cleanup) {
            if (target && target->config.Port == port) return true;
        }
        return false;
    }
};

enum class NodeTransitionMode {
    Refresh,
    Create,
    Recover,
    StageNewEndpoint,
    ReplaceInPlace,
    SwapSameEndpoint,
};

struct NodeTransitionPlan {
    NodeTransitionMode mode = NodeTransitionMode::Refresh;

    [[nodiscard]] bool Transitioning() const noexcept {
        return mode != NodeTransitionMode::Refresh;
    }

    [[nodiscard]] bool DestructiveSwap() const noexcept {
        return mode == NodeTransitionMode::SwapSameEndpoint;
    }

    [[nodiscard]] bool RetireOldInboundBeforeCommit() const noexcept {
        return mode == NodeTransitionMode::StageNewEndpoint;
    }
};

[[nodiscard]] inline bool NodeConfigChanged(
    const api::NodeInfo& current,
    const api::NodeInfo& candidate) noexcept {
    return current.Port != candidate.Port
        || current.NodeType != candidate.NodeType
        || current.TransportProtocol != candidate.TransportProtocol
        || current.Path != candidate.Path
        || current.Host != candidate.Host
        || current.EnableTLS != candidate.EnableTLS
        || current.EnableReality != candidate.EnableReality
        || current.Flow != candidate.Flow
        || current.ServiceName != candidate.ServiceName
        || current.Reality != candidate.Reality
        || current.TLSServerName != candidate.TLSServerName
        || current.CypherMethod != candidate.CypherMethod
        || current.ShadowsocksServerKey != candidate.ShadowsocksServerKey
        || current.PaddingScheme != candidate.PaddingScheme
        || current.HysteriaUpMbps != candidate.HysteriaUpMbps
        || current.HysteriaDownMbps != candidate.HysteriaDownMbps;
}

[[nodiscard]] inline NodeTransitionPlan PlanNodeTransition(
    const api::NodeInfo* current,
    bool current_started,
    const api::NodeInfo& candidate) noexcept {
    if (current == nullptr) {
        return {NodeTransitionMode::Create};
    }
    if (!current_started) {
        return {NodeTransitionMode::Recover};
    }
    if (!NodeConfigChanged(*current, candidate)) {
        return {NodeTransitionMode::Refresh};
    }
    if (current->Port != candidate.Port) {
        return {NodeTransitionMode::StageNewEndpoint};
    }
    if (current->NodeType == candidate.NodeType) {
        return {NodeTransitionMode::ReplaceInPlace};
    }
    return {NodeTransitionMode::SwapSameEndpoint};
}

[[nodiscard]] constexpr std::chrono::seconds PanelInterval(
    int configured_seconds,
    uint32_t fallback_seconds) noexcept {
    return std::chrono::seconds(
        configured_seconds > 0
            ? static_cast<uint32_t>(configured_seconds)
            : fallback_seconds);
}

struct OnlineSnapshot {
    std::vector<api::OnlineUser> entries;
    size_t user_count = 0;
};

[[nodiscard]] inline OnlineSnapshot
BuildOnlineSnapshot(std::vector<common::OnlineDevice> devices) {
    std::erase_if(devices, [](const common::OnlineDevice& d) {
        return d.user_id <= 0 || d.ip.empty();
    });
    std::sort(devices.begin(), devices.end());
    devices.erase(std::unique(devices.begin(), devices.end()), devices.end());

    OnlineSnapshot result;
    result.entries.reserve(devices.size());
    std::optional<int64_t> last_user_id;
    for (auto& device : devices) {
        if (!last_user_id || *last_user_id != device.user_id) {
            ++result.user_count;
            last_user_id = device.user_id;
        }
        result.entries.push_back(api::OnlineUser{
            .UID = device.user_id,
            .IP = std::move(device.ip),
        });
    }
    return result;
}

// One address-stable wait slot belongs to each panel fixed before Start. FIFO
// admission spans the complete all-Worker transaction, not just one publication:
// preparing a whole authentication snapshot must not race another panel's
// commit or compensation. An incomplete rollback retains exclusive recovery
// ownership without discarding the other panels' places in the queue.
class NodeMutationGate {
public:
    NodeMutationGate() = default;
    NodeMutationGate(const NodeMutationGate&) = delete;
    NodeMutationGate& operator=(const NodeMutationGate&) = delete;

    class Participant {
    public:
        Participant(NodeMutationGate& gate, net::any_io_executor executor,
                    NodeState& state)
            : gate_(gate), state_(state),
              ready_(std::move(executor), net::steady_timer::time_point::max()) {
            if (gate_.sealed_) {
                throw std::logic_error("node mutation participants are fixed at startup");
            }
        }
        Participant(const Participant&) = delete;
        Participant& operator=(const Participant&) = delete;

    private:
        friend class NodeMutationGate;
        NodeMutationGate& gate_;
        NodeState& state_;
        net::steady_timer ready_;
        Participant* next_ = nullptr;
        bool queued_ = false;
    };

    class Lease {
    public:
        Lease(Lease&& other) noexcept
            : gate_(std::exchange(other.gate_, nullptr)),
              participant_(other.participant_) {}
        ~Lease() {
            if (gate_) gate_->Release(*participant_);
        }
        Lease(const Lease&) = delete;
        Lease& operator=(const Lease&) = delete;
        Lease& operator=(Lease&&) = delete;

    private:
        friend class NodeMutationGate;
        Lease(NodeMutationGate& gate, Participant& participant) noexcept
            : gate_(&gate), participant_(&participant) {}
        NodeMutationGate* gate_;
        Participant* participant_;
    };

    void Seal() noexcept { sealed_ = true; }

    void Close() noexcept {
        closed_ = true;
        while (head_) {
            auto* participant = head_;
            head_ = participant->next_;
            participant->next_ = nullptr;
            participant->queued_ = false;
            Wake(*participant);
        }
        tail_ = nullptr;
    }

    net::awaitable<Lease> Acquire(Participant& participant) {
        if (&participant.gate_ != this || !sealed_ ||
            participant.queued_ || active_ == &participant) {
            throw std::logic_error("node mutation requires one request per registered panel");
        }
        if (closed_) throw IoSystemError(net::error::operation_aborted);
        participant.queued_ = true;
        if (tail_) tail_->next_ = &participant;
        else head_ = &participant;
        tail_ = &participant;
        Lease lease(*this, participant);
        GrantNext();
        while (active_ != &participant) {
            const auto [error] = co_await participant.ready_.async_wait(
                net::as_tuple(net::use_awaitable));
            const auto cancellation = co_await net::this_coro::cancellation_state;
            if (closed_ || cancellation.cancelled() != net::cancellation_type::none) {
                throw IoSystemError(net::error::operation_aborted);
            }
            if (error && error != net::error::operation_aborted) {
                throw IoSystemError(error);
            }
        }
        co_return std::move(lease);
    }

private:
    static void Wake(Participant& participant) noexcept {
        participant.ready_.cancel();
    }

    void Unqueue(Participant& participant) noexcept {
        Participant* previous = nullptr;
        for (auto* current = head_; current; current = current->next_) {
            if (current != &participant) {
                previous = current;
                continue;
            }
            if (previous) previous->next_ = current->next_;
            else head_ = current->next_;
            if (tail_ == current) tail_ = previous;
            current->next_ = nullptr;
            current->queued_ = false;
            return;
        }
    }

    void GrantNext() noexcept {
        if (closed_ || active_ || !head_) return;
        auto* participant = recovery_owner_ ? recovery_owner_ : head_;
        if (!participant->queued_) return;
        Unqueue(*participant);
        active_ = participant;
        Wake(*participant);
    }

    void Release(Participant& participant) noexcept {
        if (active_ == &participant) {
            recovery_owner_ = participant.state_.HasPendingCleanup() ? &participant : nullptr;
            active_ = nullptr;
        } else if (participant.queued_) {
            Unqueue(participant);
        }
        GrantNext();
    }

    Participant* head_ = nullptr;
    Participant* tail_ = nullptr;
    Participant* active_ = nullptr;
    Participant* recovery_owner_ = nullptr;
    bool sealed_ = false;
    bool closed_ = false;
};

// Operations are supplied by NodeRuntime in production. Its completion boundary
// includes all started Worker mutations, even when an operation throws.
template <typename Runtime>
net::awaitable<void> CleanPendingNodeRuntime(Runtime& runtime, NodeState& state) {
    if (!state.HasPendingCleanup()) co_return;
    if (runtime.IsStopping()) throw IoSystemError(net::error::operation_aborted);
    state.phase = NodeRuntimePhase::RecoveryRequired;
    co_await runtime.RecoverUsers();
    for (size_t i = 0; i < state.pending_cleanup.size(); ++i) {
        const auto& target = state.pending_cleanup[i];
        if (!target || (i != 0 && state.pending_cleanup[0] &&
                       target->tag == state.pending_cleanup[0]->tag)) continue;
        co_await runtime.RemoveInbound(target->tag);
        co_await runtime.RemoveOutbound(target->tag);
        co_await runtime.ClearUsers(target->tag, target->config.NodeType);
        co_await runtime.UpdateRules(target->tag, {});
    }
    if (runtime.IsStopping()) throw IoSystemError(net::error::operation_aborted);
    // Retain every target until the complete cleanup succeeds. Repeating a
    // completed removal is safe; forgetting an unfinished candidate is not.
    state.pending_cleanup = {};
    state.phase = NodeRuntimePhase::Stopped;
}

template <typename Runtime>
net::awaitable<void> ApplyNodeChange(
    Runtime& runtime, NodeState& state, std::shared_ptr<const NodeSnapshot> next) {
    const auto old = state.committed;
    if (!next) throw std::logic_error("node change requires a prepared snapshot");
    const auto plan = PlanNodeTransition(old ? &old->config : nullptr,
        state.phase == NodeRuntimePhase::Ready, next->config);
    if (!next->inbound || !next->outbound || !next->inbound->users ||
        (old && (!old->inbound || !old->outbound || !old->inbound->users))) {
        throw std::logic_error("node change requires complete prepared runtime snapshots");
    }

    co_await CleanPendingNodeRuntime(runtime, state);
    if (runtime.IsStopping()) throw IoSystemError(net::error::operation_aborted);
    const bool recovering_old = old && state.phase != NodeRuntimePhase::Ready;
    const auto& tag = next->tag;
    const std::string empty_tag;
    const auto& old_tag = old ? old->tag : empty_tag;
    const bool different_tag = old_tag != tag;

    // These shared snapshots are already allocated. Recording cleanup and
    // publishing success cannot introduce an allocation failure after effects.
    state.pending_cleanup = {recovering_old ? nullptr : old, next};
    state.phase = NodeRuntimePhase::Updating;
    struct IncompleteOnExit {
        NodeState& state;
        ~IncompleteOnExit() {
            if (state.phase == NodeRuntimePhase::Updating) {
                state.phase = NodeRuntimePhase::RecoveryRequired;
            }
        }
    } incomplete{state};

    struct MutationProgress {
        bool users_attempted = false;
        bool rules_attempted = false;
        bool outbound_attempted = false;
        bool inbound_attempted = false;
        bool old_inbound_retired = false;
        bool old_outbound_retired = false;
        bool old_users_cleared = false;
        bool old_rules_retired = false;
    } progress{};
    std::exception_ptr failure;
    try {
        if (!plan.Transitioning()) {
            if (next->rules != old->rules) {
                progress.rules_attempted = true;
                co_await runtime.UpdateRules(tag, next->rules);
            }
            if (next->inbound->users != old->inbound->users) {
                progress.users_attempted = true;
                co_await runtime.ApplyUsers(tag, *next->inbound->users);
            }
        } else {
            if (plan.DestructiveSwap()) {
                progress.old_inbound_retired = true;
                co_await runtime.RemoveInbound(old_tag);
            }
            progress.users_attempted = true;
            co_await runtime.ApplyUsers(tag, *next->inbound->users);
            progress.outbound_attempted = true;
            co_await runtime.AddOutbound(*next->outbound);
            if (different_tag || recovering_old) {
                progress.rules_attempted = true;
                co_await runtime.UpdateRules(tag, next->rules);
            }
            progress.inbound_attempted = true;
            if (!co_await runtime.AddInbound(*next->inbound)) {
                throw std::runtime_error("candidate inbound creation failed");
            }
            if (old && !recovering_old && different_tag) {
                if (plan.RetireOldInboundBeforeCommit()) {
                    progress.old_inbound_retired = true;
                    co_await runtime.RemoveInbound(old_tag);
                }
                progress.old_outbound_retired = true;
                co_await runtime.RemoveOutbound(old_tag);
                progress.old_users_cleared = true;
                co_await runtime.ClearUsers(old_tag, old->config.NodeType);
                progress.old_rules_retired = true;
                co_await runtime.UpdateRules(old_tag, {});
            }
            if (!different_tag && !recovering_old) {
                progress.rules_attempted = true;
                co_await runtime.UpdateRules(tag, next->rules);
            }
        }
        if (runtime.IsStopping()) throw IoSystemError(net::error::operation_aborted);
        state.committed = next;
        state.pending_cleanup = {};
        state.phase = NodeRuntimePhase::Ready;
        co_return;
    } catch (...) {
        failure = std::current_exception();
    }

    // Every started Worker task has already joined. Shutdown closes admission
    // and tears down the Workers; retain recovery leases rather than posting
    // fresh compensation into their closed mailboxes.
    if (runtime.IsStopping()) std::rethrow_exception(failure);
    // An ordinary cancelled pull still completes rollback while admission is
    // open, independently of the cancelled operation that triggered it.
    co_await net::this_coro::reset_cancellation_state(net::disable_cancellation());

    bool restored = true;
    try { co_await runtime.RecoverUsers(); }
    catch (...) { restored = false; }
    if (plan.Transitioning()) {
        if (progress.inbound_attempted) {
            try { co_await runtime.RemoveInbound(tag); }
            catch (...) { restored = false; }
        }
        if (progress.rules_attempted && (different_tag || recovering_old)) {
            try { co_await runtime.UpdateRules(tag, {}); }
            catch (...) { restored = false; }
        }
        if (progress.outbound_attempted && (different_tag || recovering_old)) {
            try { co_await runtime.RemoveOutbound(tag); }
            catch (...) { restored = false; }
        }
        if (progress.users_attempted && (different_tag || recovering_old)) {
            try { co_await runtime.ClearUsers(tag, next->config.NodeType); }
            catch (...) { restored = false; }
        }
    }
    if (old && !recovering_old) {
        if ((!different_tag && progress.users_attempted) || progress.old_users_cleared) {
            try { co_await runtime.ApplyUsers(old_tag, *old->inbound->users); }
            catch (...) { restored = false; }
        }
        if ((!different_tag && progress.outbound_attempted) || progress.old_outbound_retired) {
            try { co_await runtime.AddOutbound(*old->outbound); }
            catch (...) { restored = false; }
        }
        if ((!different_tag && progress.rules_attempted) || progress.old_rules_retired) {
            try { co_await runtime.UpdateRules(old_tag, old->rules); }
            catch (...) { restored = false; }
        }
        if ((!different_tag && progress.inbound_attempted) || progress.old_inbound_retired) {
            try {
                if (!co_await runtime.AddInbound(*old->inbound)) restored = false;
            } catch (...) { restored = false; }
        }
    }
    if (restored) {
        state.pending_cleanup = {};
        state.phase = (old && !recovering_old)
            ? NodeRuntimePhase::Ready
            : NodeRuntimePhase::Stopped;
    }
    // The controller may recover from an ordinary mutation failure and keep
    // serving pulls. Only rollback, not the remaining loop, shields cancellation.
    co_await net::this_coro::reset_cancellation_state(net::enable_terminal_cancellation());
    std::rethrow_exception(failure);
}

}  // namespace controller
