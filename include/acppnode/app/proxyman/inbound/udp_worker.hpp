#pragma once

#include "acppnode/app/proxyman/inbound/udp_handler.hpp"
#include "acppnode/common/buf/multi_buffer.hpp"
#include "acppnode/common/error.hpp"
#include "acppnode/transport/link.hpp"

#include <chrono>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace acpp {
struct TargetAddress;
struct StatsShard;
struct TimeoutsConfig;

namespace routing {
class Dispatcher;
}
}  // namespace acpp

namespace acpp::proxyman::inbound {

struct ReceiverSettings;

class UdpReplySink {
public:
    virtual ~UdpReplySink() noexcept = default;

    virtual void EnqueueUdpReply(const std::string& socket_key,
                                 udp::socket* sock,
                                 udp::endpoint endpoint,
                                 buf::MultiBuffer payload,
                                 uint32_t worker_id) = 0;
};

struct UdpDatagramContext {
    std::string_view socket_key;
    udp::socket* sock = nullptr;
    udp::endpoint client_endpoint;
    std::span<const uint8_t> payload;
    const ReceiverSettings* receiver = nullptr;
    net::io_context& io_context;
    routing::Dispatcher& dispatcher;
    StatsShard& stats;
    const TimeoutsConfig& timeouts;
    uint32_t worker_id = 0;
    UdpReplySink& reply_sink;
};

// ============================================================================
// UdpWorker - per-Worker UDP inbound worker
//
// 对齐 xray-core app/proxyman/inbound udpWorker 的职责起点：绑定 tag 和
// inbound UDP handler 实例。SO_REUSEPORT socket 与回包队列归属当前 Worker。
// ============================================================================
class UdpWorker final {
public:
    using SocketPtr = std::unique_ptr<udp::socket>;

    class PendingUdpReply;
    class ClientSession;
    using ClientSessionPtr = std::shared_ptr<ClientSession>;
    using ReplyCallback = ::acpp::RoutedPacketCallback;

    struct PendingUdpReplyDeleter {
        void operator()(PendingUdpReply* reply) const noexcept;
    };
    using PendingUdpReplyPtr =
        std::unique_ptr<PendingUdpReply, PendingUdpReplyDeleter>;

    UdpWorker(std::string tag, std::unique_ptr<UdpHandler> proxy);
    ~UdpWorker() noexcept;

    UdpWorker(const UdpWorker&) = delete;
    UdpWorker& operator=(const UdpWorker&) = delete;
    UdpWorker(UdpWorker&&) noexcept;
    UdpWorker& operator=(UdpWorker&&) noexcept;

    [[nodiscard]] std::string_view Tag() const noexcept;

    // Keep Worker-local sockets stable while replacing cold-path protocol state.
    [[nodiscard]] bool ReplaceHandler(std::unique_ptr<UdpHandler> proxy) noexcept;
    void Close() noexcept;

    void ProcessDatagram(const UdpDatagramContext& datagram);

    [[nodiscard]] bool EnqueueReply(const std::string& socket_key,
                                    udp::endpoint endpoint,
                                    buf::MultiBuffer payload);
    [[nodiscard]] bool EnqueueReply(const std::string& socket_key,
                                    udp::endpoint endpoint,
                                    buf::BufferGuard payload);
    [[nodiscard]] PendingUdpReplyPtr BeginReplySend(const std::string& socket_key);
    [[nodiscard]] static std::span<const net::const_buffer>
    ReplySendBuffers(const PendingUdpReply& reply) noexcept;
    [[nodiscard]] static const udp::endpoint&
    ReplyEndpoint(const PendingUdpReply& reply) noexcept;
    [[nodiscard]] bool CompleteReplySend(const std::string& socket_key);
    void ClearReplyQueue(const std::string& socket_key);

    [[nodiscard]] bool HasClientSession(const std::string& socket_key,
                                        const std::string& client_key) const noexcept;
    [[nodiscard]] ClientSessionPtr FindClientSession(
        const std::string& socket_key,
        const std::string& client_key) const noexcept;
    [[nodiscard]] ClientSessionPtr CreateClientSession(
        const std::string& socket_key,
        const std::string& client_key,
        net::io_context& io_context,
        ReplyCallback reply_callback,
        udp::endpoint reply_endpoint,
        UdpSessionOwner session_owner,
        std::chrono::steady_clock::time_point now);
    [[nodiscard]] bool PushClientPayload(const std::string& socket_key,
                                         const std::string& client_key,
                                         const TargetAddress& target,
                                         udp::endpoint reply_endpoint,
                                         const UdpSessionOwner& session_owner,
                                         buf::MultiBuffer payload,
                                         std::chrono::steady_clock::time_point now);
    void CleanupIdleClientSessions(const std::string& socket_key,
                                   std::chrono::steady_clock::time_point now,
                                   std::chrono::seconds idle_timeout);
    void CleanupClientSessions(const std::string& socket_key) noexcept;
    void CleanupAllClientSessions() noexcept;

    [[nodiscard]] static SocketPtr MakeSocket(net::io_context& io_context) {
        return std::make_unique<udp::socket>(io_context);
    }
    // A socket key belongs to one receive loop. Duplicate attachment is
    // rejected instead of cancelling and replacing the live socket.
    [[nodiscard]] udp::socket* AttachSocket(
        const std::string& socket_key,
        SocketPtr socket);
    [[nodiscard]] udp::socket* FindSocket(const std::string& socket_key) noexcept;
    [[nodiscard]] const udp::socket* FindSocket(const std::string& socket_key) const noexcept;
    [[nodiscard]] std::vector<std::string> SocketKeys() const;
    void CloseSocket(const std::string& socket_key) noexcept;
    void CloseAllSockets() noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

class UdpWorker::ClientSession final
    : public transport::MultiBufferReader,
      public transport::MultiBufferWriter {
public:
    ClientSession(net::io_context& io_context,
                  ReplyCallback reply_callback,
                  udp::endpoint reply_endpoint,
                  UdpSessionOwner session_owner);
    ~ClientSession() noexcept override;

    ClientSession(const ClientSession&) = delete;
    ClientSession& operator=(const ClientSession&) = delete;

    [[nodiscard]] bool Closed() const noexcept;
    [[nodiscard]] bool Owns(const UdpSessionOwner& owner) const noexcept;

    void UpdateReplyEndpoint(udp::endpoint endpoint) noexcept;
    [[nodiscard]] bool Push(
        const TargetAddress& target,
        buf::MultiBuffer payload);
    void Close() noexcept;

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override;
    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer mb) override;
    net::awaitable<void> WriteBuffers(std::span<const net::const_buffer> buffers) override;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace acpp::proxyman::inbound
