#pragma once

#include "common/allocator.hpp"
#include "common/buf/multi_buffer.hpp"
#include "common/buffer_util.hpp"
#include "common/error.hpp"
#include "proxy/inbound.hpp"
#include "app/session_group_executor.hpp"
#include "transport/link.hpp"
#include "udp_client_session_key.hpp"
#include "udp_resource_budget.hpp"

#include <cstdint>
#include <chrono>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>

struct TargetAddress;
struct StatsShard;
struct TimeoutsConfig;

namespace app { struct DatagramSessionEnvironment; }
namespace routing {
class Dispatcher;
}

namespace proxyman::inbound {
struct ReceiverSettings;
}

namespace worker_detail {

class UdpAssociationReclaimer;
struct UdpAssociationHook;
struct UdpHandoffRecord;

// Each encoded reply retains a lease until its actual listener send completes.
class UdpReplyFence final {
public:
    explicit UdpReplyFence(net::io_context& io) : drained_(io, 1) {}
    class Lease final {
    public:
        Lease() = default;
        explicit Lease(std::shared_ptr<UdpReplyFence> fence) : fence_(std::move(fence)) {
            if (fence_) ++fence_->pending_;
        }
        Lease(Lease&& other) noexcept : fence_(std::move(other.fence_)) {}
        Lease& operator=(Lease&& other) noexcept {
            if (this != &other) { Reset(); fence_ = std::move(other.fence_); }
            return *this;
        }
        ~Lease() { Reset(); }
        Lease(const Lease&) = delete;
        Lease& operator=(const Lease&) = delete;
    private:
        void Reset() noexcept;
        std::shared_ptr<UdpReplyFence> fence_;
    };
    net::awaitable<void> AsyncDrain();
private:
    size_t pending_ = 0;
    SignalChannel drained_;
};

class UdpReplySink {
public:
    virtual ~UdpReplySink() noexcept = default;

    [[nodiscard]] virtual bool EnqueueUdpReply(
        std::string_view socket_key,
        udp::socket* sock,
        udp::endpoint endpoint,
        buf::MultiBuffer payload,
        uint32_t worker_id,
        std::shared_ptr<UdpReplyFence> fence = {}) = 0;
};

struct UdpDatagramContext {
    std::string_view socket_key;
    udp::socket* sock = nullptr;
    udp::endpoint client_endpoint;
    std::span<const uint8_t> payload;
    const proxyman::inbound::ReceiverSettings* receiver = nullptr;
    net::io_context& io_context;
    routing::Dispatcher* dispatcher = nullptr;
    StatsShard& stats;
    const TimeoutsConfig& timeouts;
    uint32_t worker_id = 0;
    UdpReplySink& reply_sink;
    const app::DatagramSessionEnvironment* environment = nullptr;
};

// Worker-private owner for native UDP sockets, client sessions and reply queues.
class UdpIngress final : public memory::ThreadAllocated {
public:
    // Handles remain Worker-local; receive/send operations retain them only
    // across their own asynchronous cancellation boundary.
    using SocketPtr = std::shared_ptr<udp::socket>;

    struct PendingUdpReply {
        uint64_t id = 0;
        udp::endpoint endpoint;
        buf::MultiBuffer payload;
        size_t payload_size = 0;
        UdpResourceBudget::PayloadReservation reservation;
        UdpReplyFence::Lease fence;
        ConstBufferSpanBuilder<buf::MultiBuffer::kInlineCapacity> send_buffers;

        void PrepareSendBuffers();
        [[nodiscard]] std::span<const net::const_buffer> SendBuffers() const noexcept;
    };
    class ClientSession;
    using ClientSessionPtr = std::shared_ptr<ClientSession>;
    // The native response path has one concrete owner, not an erased callback.
    // sink is Worker-local and outlives all joined session/reply operations.
    struct ReplyRoute {
        memory::ThreadLocalString socket_key;
        SocketPtr socket;
        std::shared_ptr<::InboundDatagramResponse> response;
        UdpReplySink* sink = nullptr;
        uint32_t worker_id = 0;
        std::shared_ptr<UdpReplyFence> fence;

        [[nodiscard]] bool Valid() const noexcept { return response && sink; }
        [[nodiscard]] bool Send(UDPPacketView packet, const udp::endpoint& endpoint);
    };

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


    UdpIngress(std::string_view tag, std::unique_ptr<::Inbound> proxy,
               UdpAssociationReclaimer& reclaimer, UdpResourceBudget& budget,
               net::io_context& io_context);
    ~UdpIngress() noexcept;

    UdpIngress(const UdpIngress&) = delete;
    UdpIngress& operator=(const UdpIngress&) = delete;

    [[nodiscard]] std::string_view Tag() const noexcept;
    [[nodiscard]] ResourceStats GetResourceStats() const noexcept;

    // Keep Worker-local sockets stable while replacing cold-path protocol state.
    [[nodiscard]] bool ReplaceHandler(
        std::unique_ptr<::Inbound> proxy) noexcept;
    void RequestStop() noexcept;
    [[nodiscard]] net::awaitable<void> AsyncJoin();

    void ProcessDatagram(const UdpDatagramContext& datagram);

    [[nodiscard]] ReplyEnqueueResult EnqueueReply(
        std::string_view socket_key,
        udp::endpoint endpoint,
        buf::MultiBuffer payload,
        std::shared_ptr<UdpReplyFence> fence = {});
    // Hands the oldest queued datagram to the sender admitted by StartSend.
    [[nodiscard]] std::optional<PendingUdpReply> BeginReplySend(std::string_view socket_key);
    // Completes the active send and hands the next queued datagram to the same
    // sender. A stale id (cleared or replaced queue) changes nothing.
    [[nodiscard]] std::optional<PendingUdpReply> CompleteReplySend(
        std::string_view socket_key,
        uint64_t completed_id);
    void ClearReplyQueue(std::string_view socket_key);

    [[nodiscard]] ClientSessionPtr CreateClientSession(
        std::string_view socket_key,
        const ClientSessionKey& client_key,
        net::io_context& io_context,
        ReplyRoute reply,
        udp::endpoint reply_endpoint,
        ::InboundDatagramOwner session_owner,
        std::chrono::steady_clock::time_point last_active,
        std::chrono::seconds idle_timeout);
    void CleanupClientSessions(std::string_view socket_key) noexcept;
    void CleanupAllClientSessions() noexcept;

    [[nodiscard]] static SocketPtr MakeSocket(net::io_context& io_context) {
        return memory::AllocateShared<udp::socket>(io_context);
    }
    // A socket key belongs to one receive loop. Duplicate attachment is
    // rejected instead of cancelling and replacing the live socket.
    [[nodiscard]] SocketPtr AttachSocket(
        std::string_view socket_key,
        SocketPtr socket);
    [[nodiscard]] SocketPtr FindSocket(std::string_view socket_key) noexcept;
    [[nodiscard]] bool OwnsSocket(
        std::string_view socket_key,
        const udp::socket* socket) const noexcept;
    [[nodiscard]] size_t SocketCount() const noexcept;
    void CloseSocket(std::string_view socket_key) noexcept;
    void CloseAllSockets() noexcept;

private:
    friend class UdpAssociationReclaimer;
    void ReclaimAssociation(UdpAssociationHook& hook,
                            std::chrono::steady_clock::time_point now) noexcept;
    void RetireNativeJob(ClientSession& session) noexcept;
    static net::awaitable<void> RunNativeDispatch(ClientSessionPtr session);
    static net::awaitable<void> RunNativeFlow(ClientSessionPtr session);
    struct AuthenticatedPacket;
    net::awaitable<void> ProcessAuthenticated(std::shared_ptr<AuthenticatedPacket> packet);
    void ProcessDecoded(const UdpDatagramContext& datagram,
        InboundDatagramResult decoded,
        std::shared_ptr<UdpHandoffRecord> record = {},
        std::shared_ptr<InboundDatagramResponse> response = {});
    void RegisterNativeJob(const ClientSessionPtr& session);
    void DetachNativeJob(ClientSession& session) noexcept;
    void ReleaseControl() noexcept;
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

class UdpIngress::ClientSession final
    : public transport::MultiBufferReader,
      public transport::MultiBufferWriter,
      public ExecutionDomain::NativeResource {
public:
    transport::CancellationSource& Cancellation() noexcept override;

    ClientSession(net::io_context& io_context,
                  ReplyRoute reply,
                  udp::endpoint reply_endpoint,
                  ::InboundDatagramOwner session_owner,
                  UdpResourceBudget& budget,
                  UdpResourceBudget::AssociationLease association);
    ~ClientSession() noexcept override;

    ClientSession(const ClientSession&) = delete;
    ClientSession& operator=(const ClientSession&) = delete;

    [[nodiscard]] bool Closed() const noexcept;
    [[nodiscard]] bool Owns(
        const ::InboundDatagramOwner& owner) const noexcept;

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
    net::awaitable<void> PrepareHandoff(const ExecutionDomain::HandoffTarget&) override;
    void CommitHandoff(const ExecutionDomain::HandoffTarget&) noexcept override;
    net::awaitable<void> CancelHandoff(const ExecutionDomain::HandoffTarget&) override;

    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace worker_detail
