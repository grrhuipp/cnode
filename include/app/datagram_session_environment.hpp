#pragma once

#include "infra/config_types.hpp"

#include <cstdint>
#include <memory>

class ConnectionLimiter;
class UserOnlineTracker;
struct StatsShard;
namespace routing { class Dispatcher; }
namespace proxyman::inbound {
class Handler;
struct BuildRequest;
}

namespace app {
class RequestLoadState;

// 原生 UDP 与 QUIC 入口共同借用的 Worker 本地能力，不携带接收器配置。
struct DatagramSessionEnvironment final {
    TimeoutsConfig timeouts;
    routing::Dispatcher* dispatcher = nullptr;
    StatsShard* stats = nullptr;
    ConnectionLimiter* limiter = nullptr;
    RequestLoadState* request_load = nullptr;
    UserOnlineTracker* tracker = nullptr;
    uint32_t* active_sessions = nullptr;
    std::shared_ptr<proxyman::inbound::Handler> handler{};
    std::shared_ptr<const proxyman::inbound::BuildRequest> prepared{};
};

} // namespace app
