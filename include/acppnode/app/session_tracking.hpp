#pragma once

#include "acppnode/app/traffic_types.hpp"
#include "acppnode/common/asio_types.hpp"
#include "acppnode/runtime/channel.hpp"

#include <cstdint>
#include <memory>
#include <string>

namespace acpp {
namespace session { class TrafficSource; struct Traffic; }
namespace app {

class SessionTrackingState {
public:
    explicit SessionTrackingState(net::any_io_executor executor);
    ~SessionTrackingState();
    SessionTrackingState(const SessionTrackingState&) = delete;
    SessionTrackingState& operator=(const SessionTrackingState&) = delete;

    net::awaitable<void> AddUserTraffic(std::string tag, int64_t user_id,
                                        uint64_t upload, uint64_t download);
    struct Registration {
        ServiceChannel::Reservation reservation;
        uint64_t conn_id = 0;
    };
    net::awaitable<Registration> RegisterActiveSession(uint64_t conn_id, std::string tag,
        int64_t user_id, std::shared_ptr<session::TrafficSource> source);
    net::awaitable<void> UnregisterActiveSession(Registration registration,
                                                session::Traffic traffic);
    net::awaitable<UserTrafficSnapshot> CollectAndResetTraffic(std::string tag);
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace app
}  // namespace acpp
