#pragma once

#include <cstddef>
#include <cstdint>
#include <unordered_map>

namespace acpp::app {

struct UserTraffic {
    uint64_t upload = 0;
    uint64_t download = 0;
};

struct UserTrafficSnapshot {
    std::unordered_map<int64_t, UserTraffic> users;

    [[nodiscard]] bool empty() const noexcept { return users.empty(); }
    [[nodiscard]] size_t size() const noexcept { return users.size(); }

    auto begin() noexcept { return users.begin(); }
    auto end() noexcept { return users.end(); }
    auto begin() const noexcept { return users.begin(); }
    auto end() const noexcept { return users.end(); }
};

}  // namespace acpp::app
