#pragma once

#include "acppnode/app/traffic_types.hpp"
#include "acppnode/common/allocator.hpp"
#include "acppnode/common/string_hash.hpp"

#include <cstdint>
#include <string_view>

namespace acpp {

namespace session {
struct Traffic;
}  // namespace session

namespace app {

class SessionTrackingState : public memory::ThreadAllocated {
    struct Account {
        UserTraffic completed;
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

    SessionTrackingState(const SessionTrackingState&) = delete;
    SessionTrackingState& operator=(const SessionTrackingState&) = delete;
    SessionTrackingState(SessionTrackingState&&) noexcept;
    SessionTrackingState& operator=(SessionTrackingState&&) noexcept;

    void RegisterActiveSession(ActiveSession& node,
                               std::string_view tag,
                               int64_t user_id,
                               session::Traffic& traffic);

    void UnregisterActiveSession(ActiveSession& node) noexcept;

    [[nodiscard]] UserTrafficSnapshot CollectAndResetTraffic(std::string_view tag);

private:
    struct AccountBucket {
        memory::ThreadLocalUnorderedMap<int64_t, Account> traffic;
        ActiveSession* active_head = nullptr;
    };

    memory::ThreadLocalUnorderedMap<memory::ThreadLocalString,
                                    AccountBucket,
                                    TransparentStringHash,
                                    TransparentStringEq> accounts_;
};

}  // namespace app
}  // namespace acpp
