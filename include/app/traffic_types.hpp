#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>
#include <unordered_map>


class ExecutionDomain;

namespace app {

class SessionTrackingState;

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

struct DomainTrafficSnapshot {
    std::shared_ptr<SessionTrackingState> owner;
    UserTrafficCounters counters;
    std::weak_ptr<ExecutionDomain> domain;
};

struct UserTrafficSnapshot : UserTrafficCounters {
    // Commit tokens retain only the small accounting ledger. Closed physical
    // connection domains are never kept alive until the reporting interval.
    std::vector<DomainTrafficSnapshot> domains;
    [[nodiscard]] bool empty() const noexcept {
        if (!users.empty()) return false;
        for (const auto& token : domains) {
            if (!token.counters.empty()) return false;
        }
        return true;
    }
};

}  // namespace app
