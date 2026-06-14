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
    SessionTrackingState();
    ~SessionTrackingState();

    SessionTrackingState(const SessionTrackingState&) = delete;
    SessionTrackingState& operator=(const SessionTrackingState&) = delete;
    SessionTrackingState(SessionTrackingState&&) noexcept;
    SessionTrackingState& operator=(SessionTrackingState&&) noexcept;

    void AddUserTraffic(std::string_view tag,
                        int64_t user_id,
                        uint64_t upload,
                        uint64_t download);

    void RegisterActiveSession(uint64_t conn_id,
                               std::string_view tag,
                               int64_t user_id,
                               session::Traffic& traffic);

    void UnregisterActiveSession(uint64_t conn_id,
                                 const session::Traffic& traffic) noexcept;

    [[nodiscard]] UserTrafficSnapshot CollectAndResetTraffic(std::string_view tag);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace app
}  // namespace acpp
