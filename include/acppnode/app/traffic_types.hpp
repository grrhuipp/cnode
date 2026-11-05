#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>
#include <unordered_map>

namespace acpp { class ExecutionDomain; }

namespace acpp::app {

class PhysicalSessionCapabilities;

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

struct AccountingDomain {
    std::shared_ptr<PhysicalSessionCapabilities> capabilities;
    std::shared_ptr<ExecutionDomain> domain;
};

struct DomainTrafficSnapshot {
    AccountingDomain owner;
    UserTrafficCounters counters;
};

struct UserTrafficSnapshot : UserTrafficCounters {
    // Stable per-domain commit tokens survive execution-group migration.
    std::vector<DomainTrafficSnapshot> domains;
    [[nodiscard]] bool empty() const noexcept {
        if (!users.empty()) return false;
        for (const auto& token : domains) {
            if (!token.counters.empty()) return false;
        }
        return true;
    }
};

}  // namespace acpp::app
