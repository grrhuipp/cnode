#pragma once

#include "hysteria_protocol.hpp"
#include "quic_handoff.hpp"
#include "app/proxyman/inbound/prepared_config.hpp"
#include "app/session_capabilities.hpp"
#include "common/allocator.hpp"
#include "common/asio_types.hpp"
#include "common/string_hash.hpp"

#include <asio/steady_timer.hpp>
#include <openssl/ssl.h>

#include <memory>
#include <span>
#include <string_view>

namespace transport::internet::hysteria {

class Connection;
struct SocketState;

struct SslContextDeleter {
    void operator()(SSL_CTX* context) const noexcept { SSL_CTX_free(context); }
};
using SslContextPtr = std::unique_ptr<SSL_CTX, SslContextDeleter>;

// Worker-local sockets, receive staging, native send ownership and one expiry
// timer. Each accepted QUIC connection stays on its accepting Worker, shared
// by all its TCP streams and UDP sessions; listeners never transfer received
// payloads or move their shared sockets.
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
    friend class Connection;

    [[nodiscard]] const proxyman::inbound::ReceiverSettings& Receiver() const noexcept;
    void Spawn(net::awaitable<void> task);
    [[nodiscard]] bool Queue(SocketState& socket, std::span<const uint8_t> data,
                             udp::endpoint remote,
                             std::shared_ptr<Connection> connection, bool terminal = false);
    void Associate(const ngtcp2_cid& cid, std::shared_ptr<Connection> connection);
    void Dissociate(const ngtcp2_cid& cid) noexcept;
    void DissociateAll(Connection& connection) noexcept;
    SocketState* Resolve(const udp::endpoint& local) noexcept;
    void Enqueue(const std::shared_ptr<Connection>& connection,
                 const std::shared_ptr<SocketState>& socket,
                 const udp::endpoint& remote,
                 memory::ThreadLocalVector<uint8_t> bytes);
    void Pump(const std::shared_ptr<Connection>& connection);
    net::awaitable<void> ReceiveLoop(std::shared_ptr<SocketState> socket);
    net::awaitable<void> SendLoop(std::shared_ptr<SocketState> socket);
    void ArmExpiry();
    net::awaitable<void> ExpiryLoop();

    app::DatagramSessionEnvironment environment;
    memory::ThreadLocalUnorderedMap<Connection*, std::shared_ptr<Connection>> sessions;
    uint32_t worker_id;
    net::io_context& io;
    Version version = Version::V2;
    uint64_t upload_bytes_per_second = 0;
    uint64_t download_bytes_per_second = 0;
    SslContextPtr ssl_context;
    memory::ThreadLocalUnorderedMap<memory::ThreadLocalString,
        std::shared_ptr<SocketState>, TransparentStringHash, TransparentStringEq> sockets;
    memory::ThreadLocalUnorderedMap<
        ConnectionId, std::shared_ptr<Connection>, ConnectionIdHash> connections;
    net::steady_timer changed;
    net::steady_timer expiry;
    size_t tasks = 0;
    bool stopping = false;
    bool started = false;
    bool expiry_running = false;
};

}  // namespace transport::internet::hysteria
