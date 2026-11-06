#pragma once

#include "acppnode/app/proxyman/inbound/prepared_config.hpp"
#include "acppnode/common/allocator.hpp"
#include "acppnode/common/asio_types.hpp"

#include <memory>
#include <string_view>

namespace acpp {
class ConnectionLimiter;
struct StatsShard;
struct TimeoutsConfig;
class UserOnlineTracker;
namespace app { class RequestLoadState; }
namespace routing { class Dispatcher; }
namespace proxyman::inbound { class Handler; }
}  // namespace acpp

namespace acpp::transport::internet::hysteria {

class QuicListener;

// Worker-local Hysteria QUIC listener, the counterpart of Xray's
// transport/internet/hysteria hub. It owns sockets, connection IDs, timers,
// QUIC/HTTP/3 state and connection-level authentication; every authenticated
// TCP request stream and UDP session is handed to |handler| as a logical
// transport stream. Every borrowed reference belongs to the Worker that
// runs this ingress and outlives AsyncJoin.
class HysteriaIngress final : public memory::ThreadAllocated {
public:
    using SocketPtr = std::shared_ptr<udp::socket>;

    HysteriaIngress(
        uint32_t worker_id,
        net::io_context& io_context,
        routing::Dispatcher& dispatcher,
        StatsShard& stats,
        ConnectionLimiter& limiter,
        UserOnlineTracker& online_tracker,
        app::RequestLoadState& request_load,
        const TimeoutsConfig& timeouts,
        const proxyman::inbound::BuildRequest& request,
        std::shared_ptr<proxyman::inbound::Handler> handler);
    ~HysteriaIngress() noexcept;

    HysteriaIngress(const HysteriaIngress&) = delete;
    HysteriaIngress& operator=(const HysteriaIngress&) = delete;

    [[nodiscard]] SocketPtr MakeSocket();
    [[nodiscard]] SocketPtr AttachSocket(
        std::string_view socket_key, SocketPtr socket);

    void Start();
    void RequestStop() noexcept;
    net::awaitable<void> AsyncJoin();

private:
    std::unique_ptr<QuicListener> listener_;
};

}  // namespace acpp::transport::internet::hysteria
