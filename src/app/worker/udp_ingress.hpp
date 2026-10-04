#pragma once

#include "acppnode/common/allocator.hpp"
#include "acppnode/common/buf/multi_buffer.hpp"
#include "acppnode/common/error.hpp"
#include "acppnode/proxy/inbound.hpp"
#include "acppnode/transport/link.hpp"

#include <chrono>
#include <memory>
#include <span>
#include <string>
#include <string_view>

namespace acpp {
struct TargetAddress;
struct StatsShard;
struct TimeoutsConfig;

namespace routing {
class Dispatcher;
}

namespace proxyman::inbound {
struct ReceiverSettings;
}
}  // namespace acpp

namespace acpp::worker_detail {

class UdpAssociationReclaimer;
struct UdpAssociationHook;

class UdpReplySink {
public:
    virtual ~UdpReplySink() noexcept = default;

    [[nodiscard]] virtual bool EnqueueUdpReply(
        const std::string& socket_key,
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
    const proxyman::inbound::ReceiverSettings* receiver = nullptr;
    net::io_context& io_context;
    routing::Dispatcher& dispatcher;
    StatsShard& stats;
    const TimeoutsConfig& timeouts;
    uint32_t worker_id = 0;
    uint64_t runtime_generation = 1;
    uint64_t config_generation = 1;
    UdpReplySink& reply_sink;
};

// Worker-private owner for native UDP sockets, client sessions and reply queues.
class UdpIngress final : public memory::ThreadAllocated {
public:
    // Handles remain Worker-local; receive/send operations retain them only
    // across their own asynchronous cancellation boundary.
    using SocketPtr = std::shared_ptr<udp::socket>;

    class PendingUdpReply;
    class ClientSession;
    using ClientSessionPtr = std::shared_ptr<ClientSession>;
    using ReplyCallback = ::acpp::RoutedPacketCallback;

    enum class ReplyEnqueueResult : uint8_t {
        Rejected,
        Queued,
        StartSend,
    };

    struct ResourceStats {
        size_t associations = 0;
        size_t closed_associations = 0;
        uint64_t input_datagrams = 0;
        uint64_t input_bytes = 0;
        uint64_t reply_datagrams = 0;
        uint64_t reply_bytes = 0;
        size_t active_reply_senders = 0;
        size_t native_dispatches = 0;
    };

    struct PendingUdpReplyDeleter {
        void operator()(PendingUdpReply* reply) const noexcept;
    };
    using PendingUdpReplyPtr =
        std::unique_ptr<PendingUdpReply, PendingUdpReplyDeleter>;

    UdpIngress(std::string tag, std::unique_ptr<::acpp::Inbound> proxy,
               UdpAssociationReclaimer& reclaimer, net::io_context& io_context);
    ~UdpIngress() noexcept;

    UdpIngress(const UdpIngress&) = delete;
    UdpIngress& operator=(const UdpIngress&) = delete;

    [[nodiscard]] std::string_view Tag() const noexcept;
    [[nodiscard]] ResourceStats GetResourceStats() const noexcept;

    // Keep Worker-local sockets stable while replacing cold-path protocol state.
    [[nodiscard]] bool ReplaceHandler(
        std::unique_ptr<::acpp::Inbound> proxy) noexcept;
    void RequestStop() noexcept;
    [[nodiscard]] net::awaitable<void> AsyncJoin();

    void ProcessDatagram(const UdpDatagramContext& datagram);

    [[nodiscard]] ReplyEnqueueResult EnqueueReply(
        const std::string& socket_key,
        udp::endpoint endpoint,
        buf::MultiBuffer payload);
    [[nodiscard]] ReplyEnqueueResult EnqueueReply(
        const std::string& socket_key,
        udp::endpoint endpoint,
        buf::BufferGuard payload);
    [[nodiscard]] PendingUdpReplyPtr BeginReplySend(const std::string& socket_key);
    [[nodiscard]] static std::span<const net::const_buffer>
    ReplySendBuffers(const PendingUdpReply& reply) noexcept;
    [[nodiscard]] static const udp::endpoint&
    ReplyEndpoint(const PendingUdpReply& reply) noexcept;
    [[nodiscard]] bool CompleteReplySend(
        const std::string& socket_key,
        const PendingUdpReply& completed_reply);
    void ClearReplyQueue(std::string_view socket_key);

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
        ::acpp::InboundDatagramOwner session_owner,
        std::chrono::steady_clock::time_point now,
        std::chrono::seconds idle_timeout);
    [[nodiscard]] bool PushClientPayload(const std::string& socket_key,
                                         const std::string& client_key,
                                         const TargetAddress& target,
                                         udp::endpoint reply_endpoint,
                                         const ::acpp::InboundDatagramOwner& session_owner,
                                         buf::MultiBuffer payload,
                                         std::chrono::steady_clock::time_point now);
    void CleanupClientSessions(std::string_view socket_key) noexcept;
    void CleanupAllClientSessions() noexcept;

    [[nodiscard]] static SocketPtr MakeSocket(net::io_context& io_context) {
        return memory::AllocateShared<udp::socket>(io_context);
    }
    // A socket key belongs to one receive loop. Duplicate attachment is
    // rejected instead of cancelling and replacing the live socket.
    [[nodiscard]] SocketPtr AttachSocket(
        const std::string& socket_key,
        SocketPtr socket);
    [[nodiscard]] SocketPtr FindSocket(const std::string& socket_key) noexcept;
    [[nodiscard]] std::shared_ptr<const udp::socket> FindSocket(
        const std::string& socket_key) const noexcept;
    [[nodiscard]] bool OwnsSocket(
        const std::string& socket_key,
        const udp::socket* socket) const noexcept;
    void CloseSocket(std::string_view socket_key) noexcept;
    void CloseAllSockets() noexcept;

private:
    friend class UdpAssociationReclaimer;
    void ReclaimAssociation(UdpAssociationHook& hook,
                            std::chrono::steady_clock::time_point now) noexcept;
    void FinishNativeJob(ClientSession& session) noexcept;
    void RollbackNativeJob(ClientSession& session) noexcept;
    void RetireNativeJob(ClientSession& session) noexcept;
    static net::awaitable<void> RunNativeDispatch(ClientSessionPtr session);
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

class UdpIngress::ClientSession final
    : public transport::MultiBufferReader,
      public transport::MultiBufferWriter {
public:
    transport::CancellationSource& Cancellation() noexcept override;

    ClientSession(net::io_context& io_context,
                  ReplyCallback reply_callback,
                  udp::endpoint reply_endpoint,
                  ::acpp::InboundDatagramOwner session_owner);
    ~ClientSession() noexcept override;

    ClientSession(const ClientSession&) = delete;
    ClientSession& operator=(const ClientSession&) = delete;

    [[nodiscard]] bool Closed() const noexcept;
    [[nodiscard]] bool Owns(
        const ::acpp::InboundDatagramOwner& owner) const noexcept;

    void UpdateReplyEndpoint(udp::endpoint endpoint) noexcept;
    [[nodiscard]] bool Push(
        const TargetAddress& target,
        buf::MultiBuffer payload);
    void Close() noexcept;

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override;
    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer mb) override;

private:
    friend class UdpIngress;
    void CloseWithError(ErrorCode error) noexcept;

    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace acpp::worker_detail
