#pragma once

#include "app/proxyman/inbound/prepared_config.hpp"
#include "common/allocator.hpp"
#include "common/asio_types.hpp"
#include "app/session_capabilities.hpp"

#include <memory>
#include <string_view>

namespace transport::internet::hysteria {

class QuicListener;

// Worker-local sockets, receive staging and protocol expiry. Each accepted
// QUIC connection has an independent stable capability/domain, shared by all
// its TCP streams and UDP sessions. A different receiving Worker may claim
// that domain only after exclusive QUIC path validation; listeners never
// transfer received payloads or move their shared sockets.
class HysteriaIngress final : public memory::ThreadAllocated {
public:
    using SocketPtr = std::shared_ptr<udp::socket>;

    HysteriaIngress(uint32_t worker_id, net::io_context& io_context,
                   app::DatagramSessionEnvironment environment);
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

}  // namespace transport::internet::hysteria
