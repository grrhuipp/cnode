#pragma once

#include "app/proxyman/inbound/handler.hpp"
#include "app/proxyman/inbound/prepared_config.hpp"
#include "infra/runtime_config_types.hpp"

#include <cstdint>
#include <memory>

class ConnectionLimiter;
class UserOnlineTracker;
struct StatsShard;
namespace routing { class Dispatcher; }
namespace app {
class RequestLoadState;

struct DatagramSessionEnvironment final {
    TimeoutsConfig timeouts;
    routing::Dispatcher* dispatcher = nullptr;
    StatsShard* stats = nullptr;
    ConnectionLimiter* limiter = nullptr;
    RequestLoadState* request_load = nullptr;
    UserOnlineTracker* tracker = nullptr;
    uint32_t* active_sessions = nullptr;
    std::shared_ptr<proxyman::inbound::Handler> handler;
    std::shared_ptr<const proxyman::inbound::BuildRequest> prepared;
};

} // namespace app
