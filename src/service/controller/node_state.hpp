#pragma once

#include "acppnode/api/api.hpp"
#include "acppnode/app/proxyman/inbound/prepared_config.hpp"

#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace acpp::controller {

// Constructed before runtime mutations and immutable after publication.
struct NodeSnapshot {
    api::NodeInfo config;
    std::vector<api::UserInfo> users;
    std::vector<api::DetectRule> rules;
    std::string protocol;
    std::string tag;
};

enum class NodeRuntimePhase { Stopped, Ready, Updating, RecoveryRequired };

struct NodeState {
    std::shared_ptr<const NodeSnapshot> committed;
    NodeRuntimePhase phase = NodeRuntimePhase::Stopped;
    // A failed transition can leave only its old and candidate tags behind.
    // No new transition starts until both have been cleaned successfully.
    std::array<std::shared_ptr<const NodeSnapshot>, 2> pending_cleanup;

    [[nodiscard]] bool HasPendingCleanup() const noexcept {
        return pending_cleanup[0] || pending_cleanup[1];
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

struct PreparedNodeChange {
    std::shared_ptr<const NodeSnapshot> next;
    proxyman::inbound::UserSet users;
    std::optional<proxyman::inbound::UserSet> previous_users;
    bool replace_users = true;
    bool replace_rules = true;
};

}  // namespace acpp::controller
