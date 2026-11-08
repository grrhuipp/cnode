#pragma once

#include "app/traffic_types.hpp"
#include "common/string_hash.hpp"

#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_map>


namespace session {
struct Traffic;
}  // namespace session

namespace app {

class SessionTrackingState {
    struct Account {
        UserTraffic completed;
        UserTraffic snapshotted;
        size_t active = 0;
    };
    struct AccountBucket;

public:
    struct ActiveSession {
        ActiveSession* prev = nullptr;
        ActiveSession* next = nullptr;
        int64_t user_id = 0;
        session::Traffic* traffic = nullptr;
        uint64_t last_reported_up = 0;
        uint64_t last_reported_down = 0;
        bool linked = false;
        AccountBucket* bucket = nullptr;
        Account* account = nullptr;
    };

    SessionTrackingState();
    ~SessionTrackingState();

    // Active sessions borrow bucket and account addresses inside this owner.
    SessionTrackingState(const SessionTrackingState&) = delete;
    SessionTrackingState& operator=(const SessionTrackingState&) = delete;
    SessionTrackingState(SessionTrackingState&&) = delete;
    SessionTrackingState& operator=(SessionTrackingState&&) = delete;

    void RegisterActiveSession(ActiveSession& node,
                               std::string_view tag,
                               int64_t user_id,
                               session::Traffic& traffic);

    void UnregisterActiveSession(ActiveSession& node) noexcept;

    [[nodiscard]] UserTrafficCounters SnapshotTraffic(std::string_view tag);
    // Deduct only an already-durable snapshot. Later traffic remains pending.
    void CommitTraffic(std::string_view tag, const UserTrafficCounters& snapshot);
    // Re-expose a failed durable snapshot without touching later traffic.
    void RollbackTraffic(std::string_view tag, const UserTrafficCounters& snapshot);
    // Move counters not covered by an in-flight snapshot into another ledger.
    [[nodiscard]] UserTrafficCounters ExtractAvailableTraffic(std::string_view tag);
    void MergeCompletedTraffic(std::string_view tag, UserTrafficCounters& source);

private:
    struct AccountBucket {
        std::string_view key;
        std::unordered_map<int64_t, Account> traffic;
        ActiveSession* active_head = nullptr;
    };

    std::unordered_map<std::string,
                       AccountBucket,
                       TransparentStringHash,
                       TransparentStringEq> accounts_;
};

}  // namespace app
