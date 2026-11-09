#pragma once

#include "common/string_hash.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_map>


namespace session {
struct Traffic;
}  // namespace session

namespace app {

struct UserTraffic {
    uint64_t upload = 0;
    uint64_t download = 0;
};

struct UserTrafficCounters {
    std::unordered_map<int64_t, UserTraffic> users;

    [[nodiscard]] bool empty() const noexcept { return users.empty(); }
    [[nodiscard]] size_t size() const noexcept { return users.size(); }

    auto begin() noexcept { return users.begin(); }
    auto end() noexcept { return users.end(); }
    auto begin() const noexcept { return users.begin(); }
    auto end() const noexcept { return users.end(); }
};

using UserTrafficSnapshot = UserTrafficCounters;

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
