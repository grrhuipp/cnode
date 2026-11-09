#pragma once

#include "common/allocator.hpp"
#include "common/buf/multi_buffer.hpp"
#include "common/buffer_util.hpp"
#include "common/error.hpp"
#include "common/session.hpp"
#include "common/sharded_user_stats.hpp"
#include "features/routing/dispatcher.hpp"
#include "infra/config_types.hpp"
#include "proxy/inbound.hpp"
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

class UdpReplySink {
public:
    virtual ~UdpReplySink() noexcept = default;

    [[nodiscard]] virtual bool EnqueueUdpReply(
        std::string_view socket_key,
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
        buf::MultiBuffer payload);
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

private:
    friend class UdpAssociationReclaimer;
    void ReclaimAssociation(UdpAssociationHook& hook,
                            std::chrono::steady_clock::time_point now) noexcept;
    void RetireNativeJob(ClientSession& session) noexcept;
    static net::awaitable<void> RunNativeDispatch(ClientSessionPtr session);
    void ProcessDecoded(const UdpDatagramContext& datagram,
        const net::ip::address& client_address,
        InboundDatagramResult decoded,
        std::shared_ptr<UdpHandoffRecord> record = {});
    void RegisterNativeJob(const ClientSessionPtr& session);
    void DetachNativeJob(ClientSession& session) noexcept;
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

class UdpIngress::ClientSession final
    : public transport::MultiBufferReader,
      public transport::MultiBufferWriter {
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

    struct RequestData {
        explicit RequestData(routing::DispatchPolicy dispatch_policy)
            : context(), policy(std::move(dispatch_policy)) {}
        session::Context context;
        routing::DispatchPolicy policy;
        routing::Dispatcher* dispatcher = nullptr;
        net::io_context* io_context = nullptr;
        StatsShard* stats = nullptr;
        TimeoutsConfig timeouts;
        uint32_t worker_id = 0;
        // Owned copy of the authenticating credential's profile.
        UserProfile profile;
        UserOnlineTracker* tracker = nullptr;
        ConnectionLimiter* limiter = nullptr;
        uint32_t* active_sessions = nullptr;
    };

    struct QueuedInput {
        buf::MultiBuffer payload;
        size_t bytes = 0;
        UdpResourceBudget::PayloadReservation reservation;
    };

    void WakeReader() {
        (void)reader_signal_.try_send(IoErrorCode{});
    }
    void CloseWithError(ErrorCode error) noexcept;

    UdpResourceBudget::AssociationLease association_;
    UdpResourceBudget* budget_;
    SignalChannel reader_signal_;
    ReplyRoute reply_;
    udp::endpoint reply_endpoint_;
    memory::ThreadLocalDeque<QueuedInput> input_queue_;
    size_t queued_bytes_ = 0;
    bool closed_ = false;
    ErrorCode terminal_error_ = ErrorCode::OK;
    ::InboundDatagramOwner session_owner_;
    transport::CancellationSource cancellation_;
    std::optional<RequestData> request_;
    ClientSession* job_previous_ = nullptr;
    ClientSession* job_next_ = nullptr;
    ClientSession* notify_next_ = nullptr;
    std::weak_ptr<ClientSession> job_pin_;
    UdpIngress::ClientSessionPtr notification_pin_;
    bool job_registered_ = false;
    bool job_linked_ = false;
    // The row hook naming this session as its live link; cleared on unlink.
    UdpAssociationHook* association_hook_ = nullptr;
    std::shared_ptr<UdpHandoffRecord> handoff_record_;
    UdpIngress* owner_ = nullptr;
};

}  // namespace worker_detail
