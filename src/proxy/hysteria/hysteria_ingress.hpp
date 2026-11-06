#pragma once

#include "acppnode/app/proxyman/inbound/prepared_config.hpp"
#include "acppnode/app/proxyman/inbound/receiver_settings.hpp"
#include "acppnode/common/asio_types.hpp"
#include "acppnode/common/allocator.hpp"

#include <memory>
#include <string_view>

namespace acpp {
class ConnectionLimiter;
class StatsShard;
class UserOnlineTracker;
struct TimeoutsConfig;
namespace routing { class Dispatcher; }
namespace proxy::hysteria {

class HysteriaIngress final : public memory::ThreadAllocated {
public:
    using SocketPtr = std::shared_ptr<udp::socket>;

    HysteriaIngress(
        uint32_t worker_id,
        net::io_context& io_context,
        routing::Dispatcher& dispatcher,
        StatsShard& stats,
        std::shared_ptr<ConnectionLimiter> limiter,
        UserOnlineTracker& online_tracker,
        TimeoutsConfig timeouts,
        std::shared_ptr<const proxyman::inbound::BuildRequest> request,
        std::shared_ptr<const proxyman::inbound::ReceiverSettings> receiver);
    ~HysteriaIngress() noexcept;

    HysteriaIngress(const HysteriaIngress&) = delete;
    HysteriaIngress& operator=(const HysteriaIngress&) = delete;

    [[nodiscard]] SocketPtr MakeSocket();
    [[nodiscard]] SocketPtr AttachSocket(
        std::string_view socket_key, SocketPtr socket);
    [[nodiscard]] bool OwnsSocket(
        std::string_view socket_key, const udp::socket* socket) const noexcept;

    void Start();
    void RequestStop() noexcept;
    net::awaitable<void> AsyncJoin();

    [[nodiscard]] std::string_view Tag() const noexcept;
    [[nodiscard]] size_t ConnectionCount() const noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace proxy::hysteria
}  // namespace acpp
