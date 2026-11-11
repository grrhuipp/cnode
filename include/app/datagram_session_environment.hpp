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
struct AdmissionEnvironment;
}

namespace app {
class RequestLoadState;

// 原生 UDP 与 QUIC 入口共同借用的 Worker 本地能力，不携带接收器配置。
struct DatagramSessionEnvironment final {
    TimeoutsConfig timeouts;
    routing::Dispatcher* dispatcher = nullptr;
    const proxyman::inbound::AdmissionEnvironment* admission = nullptr;
    RequestLoadState* request_load = nullptr;
    std::shared_ptr<proxyman::inbound::Handler> handler{};
    std::shared_ptr<const proxyman::inbound::BuildRequest> prepared{};
};

} // namespace app
