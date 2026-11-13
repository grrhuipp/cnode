#pragma once

#include "infra/config_types.hpp"

#include <cstdint>
#include <memory>

namespace app {

class ConnectionLimiter;

}  // namespace app
namespace common {

class UserOnlineTracker;

}  // namespace common
namespace app {

struct StatsShard;

}  // namespace app
namespace routing { class Dispatcher; }
namespace app {
class InboundHandler;
struct BuildRequest;
struct AdmissionEnvironment;
class RequestLoadState;

// 原生 UDP 与 QUIC 入口共同借用的 Worker 本地能力，不携带接收器配置。
struct DatagramSessionEnvironment final {
    infra::TimeoutsConfig timeouts;
    routing::Dispatcher* dispatcher = nullptr;
    const AdmissionEnvironment* admission = nullptr;
    RequestLoadState* request_load = nullptr;
    std::shared_ptr<InboundHandler> handler{};
    std::shared_ptr<const BuildRequest> prepared{};
};

} // namespace app
