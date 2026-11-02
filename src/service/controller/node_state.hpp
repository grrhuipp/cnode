#pragma once

#include "acppnode/api/api.hpp"
#include "acppnode/app/proxyman/inbound/prepared_config.hpp"
#include "acppnode/app/proxyman/inbound/user_store.hpp"
#include "acppnode/app/proxyman/outbound/prepared_config.hpp"
#include "inboundbuilder.hpp"

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
    std::string users_etag;
    std::string config_etag;
    std::vector<rule::DetectRule> rules;
    std::string protocol;
    std::string tag;
    std::shared_ptr<const InboundBuild> inbound;
    std::shared_ptr<const proxyman::outbound::PreparedOutboundConfig> outbound;
    std::shared_ptr<const proxyman::inbound::UserSet> prepared_users;
};

enum class NodeRuntimePhase { Stopped, Ready, Updating, RecoveryRequired };

struct UserPublicationRecovery {
    proxyman::inbound::UserStore::PublishedSnapshot previous;
    std::vector<proxyman::inbound::UserStore::WorkerView> worker_views;
};

struct NodeState {
    std::shared_ptr<const NodeSnapshot> committed;
    NodeRuntimePhase phase = NodeRuntimePhase::Stopped;
    // A failed transition can leave only its old and candidate tags behind.
    // No new transition starts until both have been cleaned successfully.
    std::array<std::shared_ptr<const NodeSnapshot>, 2> pending_cleanup;
    std::optional<UserPublicationRecovery> user_recovery;

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

}  // namespace acpp::controller
