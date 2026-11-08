#pragma once

#include "api/api.hpp"
#include "app/prepared_inbound.hpp"
#include "app/runtime_publication.hpp"
#include "app/proxyman/outbound/prepared_config.hpp"

#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace controller {

// Constructed before runtime mutations and immutable after publication.
struct NodeSnapshot {
    api::NodeInfo config;
    std::vector<api::UserInfo> users;
    std::string users_etag;
    std::string config_etag;
    std::vector<rule::DetectRule> rules;
    std::string protocol;
    std::string tag;
    // Prepared by the shared inbound builder; carries the prepared users.
    std::shared_ptr<const PreparedInbound> inbound;
    std::shared_ptr<const proxyman::outbound::PreparedOutboundConfig> outbound;
};

enum class NodeRuntimePhase { Stopped, Ready, Updating, RecoveryRequired };

struct NodeState {
    std::shared_ptr<const NodeSnapshot> committed;
    NodeRuntimePhase phase = NodeRuntimePhase::Stopped;
    // A failed transition can leave only its old and candidate tags behind.
    // No new transition starts until both have been cleaned successfully.
    std::array<std::shared_ptr<const NodeSnapshot>, 2> pending_cleanup;
    std::optional<UserPublicationRollback> user_recovery;

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

struct PreparedNodeChange {
    std::shared_ptr<const NodeSnapshot> next;
    bool replace_users = true;
    bool replace_rules = true;
};

}  // namespace controller
