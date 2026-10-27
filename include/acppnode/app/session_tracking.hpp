#pragma once

#include "acppnode/app/traffic_types.hpp"

#include <cstdint>
#include <memory>
#include <string_view>

namespace acpp {

namespace session {
struct Traffic;
}  // namespace session

namespace app {

class SessionTrackingState {
public:
    struct ActiveSession {
        ActiveSession* prev = nullptr;
        ActiveSession* next = nullptr;
        std::string_view tag;
        int64_t user_id = 0;
        session::Traffic* traffic = nullptr;
        uint64_t last_reported_up = 0;
        uint64_t last_reported_down = 0;
        bool linked = false;
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
                               session::Traffic& traffic) noexcept;

    void UnregisterActiveSession(ActiveSession& node) noexcept;

    [[nodiscard]] UserTrafficSnapshot CollectAndResetTraffic(std::string_view tag);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace app
}  // namespace acpp
