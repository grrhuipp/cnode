#pragma once

#include "app/proxyman/inbound/handler.hpp"
#include "common/allocator.hpp"
#include "common/buf/multi_buffer.hpp"
#include "common/buffer_util.hpp"
#include "common/container_util.hpp"
#include "common/error.hpp"
#include "common/ip_utils.hpp"
#include "common/session.hpp"
#include "common/sharded_user_stats.hpp"
#include "common/string_hash.hpp"
#include "features/routing/dispatcher.hpp"
#include "infra/config_types.hpp"
#include "proxy/inbound.hpp"
#include "transport/internet/timeout_scheduler.hpp"
#include "transport/link.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <limits>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>

struct TargetAddress;
struct StatsShard;
struct TimeoutsConfig;

namespace routing {
class Dispatcher;
}

namespace proxyman::inbound {
struct ReceiverSettings;
}

namespace worker_detail {

class UdpIngress;

struct ClientSessionKey final {
    ClientSessionKey(InboundDatagramOwner authenticated_owner,
                     std::optional<uint64_t> protocol_session_id,
                     udp::endpoint client_endpoint = {},
                     const proxyman::inbound::ProtocolSettings* configuration_identity = nullptr) noexcept
        : owner(authenticated_owner), session_id(protocol_session_id),
          endpoint(protocol_session_id ? udp::endpoint{} :
              udp::endpoint(iputil::NormalizeAddress(client_endpoint.address()), client_endpoint.port())),
          configuration(configuration_identity) {}

    [[nodiscard]] bool operator==(const ClientSessionKey& other) const noexcept {
        return configuration == other.configuration && owner.Same(other.owner) &&
            session_id == other.session_id && (session_id.has_value() || endpoint == other.endpoint);
    }

    InboundDatagramOwner owner;
    std::optional<uint64_t> session_id;
    udp::endpoint endpoint;
    const proxyman::inbound::ProtocolSettings* configuration = nullptr;
};

struct ClientSessionKeyHash final {
    [[nodiscard]] size_t operator()(const ClientSessionKey& key) const noexcept {
        size_t hash = 2166136261u;
        const auto mix = [&hash](uint8_t byte) noexcept {
            hash = (hash ^ byte) * 16777619u;
        };
        const auto configuration = reinterpret_cast<uintptr_t>(key.configuration);
        for (size_t shift = 0; shift < sizeof(configuration) * 8; shift += 8)
            mix(static_cast<uint8_t>(configuration >> shift));
        mix(key.owner.size);
        for (size_t i = 0; i < key.owner.size; ++i) mix(key.owner.bytes[i]);
        mix(key.session_id.has_value());
        if (key.session_id) {
            for (unsigned shift = 0; shift < 64; shift += 8)
                mix(static_cast<uint8_t>(*key.session_id >> shift));
        } else {
            const auto& address = key.endpoint.address();
            mix(address.is_v4() ? 4 : 6);
            if (address.is_v4()) {
                for (auto byte : address.to_v4().to_bytes()) mix(byte);
            } else {
                const auto v6 = address.to_v6();
                for (auto byte : v6.to_bytes()) mix(byte);
                const auto scope = v6.scope_id();
                for (size_t shift = 0; shift < sizeof(scope) * 8; shift += 8)
                    mix(static_cast<uint8_t>(scope >> shift));
            }
            mix(static_cast<uint8_t>(key.endpoint.port() >> 8));
            mix(static_cast<uint8_t>(key.endpoint.port()));
        }
        return hash;
    }
};

// Worker-local UDP association and payload capacity budget.
class UdpResourceBudget final {
public:
    struct Limits {
        size_t associations = 4096;
        size_t datagrams = 8192;
        size_t payload_capacity = 64 * 1024 * 1024;
    };
    struct Usage {
        size_t associations = 0;
        size_t datagrams = 0;
        size_t payload_capacity = 0;
    };

    class AssociationLease final {
    public:
        AssociationLease() noexcept = default;
        ~AssociationLease() { Reset(); }
        AssociationLease(const AssociationLease&) = delete;
        AssociationLease& operator=(const AssociationLease&) = delete;
        AssociationLease(AssociationLease&& other) noexcept
            : budget_(std::exchange(other.budget_, nullptr)) {}
        AssociationLease& operator=(AssociationLease&& other) noexcept {
            if (this != &other) {
                Reset();
                budget_ = std::exchange(other.budget_, nullptr);
            }
            return *this;
        }
        explicit operator bool() const noexcept { return budget_ != nullptr; }
    private:
        friend class UdpResourceBudget;
        explicit AssociationLease(UdpResourceBudget& budget) noexcept : budget_(&budget) {}
        void Reset() noexcept {
            if (budget_) --budget_->associations_;
            budget_ = nullptr;
        }
        UdpResourceBudget* budget_ = nullptr;
    };

    class PayloadReservation final {
    public:
        PayloadReservation() noexcept = default;
        ~PayloadReservation() { Reset(); }
        PayloadReservation(const PayloadReservation&) = delete;
        PayloadReservation& operator=(const PayloadReservation&) = delete;
        PayloadReservation(PayloadReservation&& other) noexcept
            : budget_(std::exchange(other.budget_, nullptr)), capacity_(other.capacity_) {}
        PayloadReservation& operator=(PayloadReservation&& other) noexcept {
            if (this != &other) {
                Reset();
                budget_ = std::exchange(other.budget_, nullptr);
                capacity_ = other.capacity_;
            }
            return *this;
        }
        explicit operator bool() const noexcept { return budget_ != nullptr; }
    private:
        friend class UdpResourceBudget;
        PayloadReservation(UdpResourceBudget& budget, size_t capacity) noexcept
            : budget_(&budget), capacity_(capacity) {}
        void Reset() noexcept {
            if (budget_) {
                --budget_->datagrams_;
                budget_->payload_capacity_ -= capacity_;
            }
            budget_ = nullptr;
        }
        UdpResourceBudget* budget_ = nullptr;
        size_t capacity_ = 0;
    };

    UdpResourceBudget() noexcept = default;
    explicit UdpResourceBudget(Limits limits) noexcept : limits_(limits) {}
    UdpResourceBudget(const UdpResourceBudget&) = delete;
    UdpResourceBudget& operator=(const UdpResourceBudget&) = delete;

    [[nodiscard]] Usage GetUsage() const noexcept {
        return {associations_, datagrams_, payload_capacity_};
    }
    [[nodiscard]] AssociationLease AcquireAssociation() noexcept {
        if (!Acquire(associations_, 1, limits_.associations)) return {};
        return AssociationLease{*this};
    }
    [[nodiscard]] PayloadReservation ReservePayload(const buf::MultiBuffer& payload) noexcept {
        size_t capacity = 0;
        for (const auto* buffer : payload) {
            if (!buffer) continue;
            if (capacity > std::numeric_limits<size_t>::max() - buf::Buffer::kSize)
                return {};
            capacity += buf::Buffer::kSize;
        }
        if (!Acquire(datagrams_, 1, limits_.datagrams)) return {};
        if (!Acquire(payload_capacity_, capacity, limits_.payload_capacity)) {
            --datagrams_;
            return {};
        }
        return PayloadReservation{*this, capacity};
    }

private:
    static bool Acquire(size_t& counter, size_t amount, size_t limit) noexcept {
        if (amount > limit || counter > limit - amount) return false;
        counter += amount;
        return true;
    }
    Limits limits_;
    size_t associations_ = 0;
    size_t datagrams_ = 0;
    size_t payload_capacity_ = 0;
};

// Embedded in an association row; its address is stable while registered.
struct UdpAssociationHook final {
    using TimePoint = std::chrono::steady_clock::time_point;

    UdpIngress* owner = nullptr;
    std::string_view socket_key;
    const ClientSessionKey* client_key = nullptr;
    std::chrono::seconds idle_timeout{};
    // Valid uplink activity only; the reclaimer re-checks it lazily when the
    // row's deadline passes, so packets never re-key the maintenance heap.
    TimePoint last_active{};
    // Earliest instant the row may need reclaiming. Uplink activity does not
    // move it; a due open row is re-checked against its last activity and
    // re-armed. min() marks a closed row, max() an open row that never expires.
    TimePoint deadline{};
    std::size_t heap_index = 0;
};

// Idle expiry of a row last active at `last_active`; max() when disabled.
[[nodiscard]] UdpAssociationHook::TimePoint UdpAssociationExpiry(
    UdpAssociationHook::TimePoint last_active, std::chrono::seconds idle_timeout) noexcept;

// Worker-local min-heap over association rows embedded in UdpIngress maps.
// One maintenance event sleeps until the nearest row deadline and reclaims at
// most a bounded batch per wake; no timer runs while no row can expire.
class UdpAssociationReclaimer final : private TimeoutEvent {
public:
    using FailureCallback = void (*)(void*, std::exception_ptr);
    using TimePoint = UdpAssociationHook::TimePoint;

    UdpAssociationReclaimer(TimeoutScheduler& scheduler,
                            void* failure_context,
                            FailureCallback on_failure) noexcept;
    ~UdpAssociationReclaimer() noexcept;
    UdpAssociationReclaimer(const UdpAssociationReclaimer&) = delete;
    UdpAssociationReclaimer& operator=(const UdpAssociationReclaimer&) = delete;

    // The only allocating step: call before inserting a row so Register
    // cannot fail once the row exists.
    void ReserveRow();
    void Register(UdpAssociationHook& hook, UdpIngress& owner,
                  std::string_view socket_key, const ClientSessionKey& client_key,
                  std::chrono::seconds idle_timeout, TimePoint deadline) noexcept;
    // Moves a registered row to a new deadline; unregistered hooks are ignored.
    void Rearm(UdpAssociationHook& hook, TimePoint deadline) noexcept;
    void Unregister(UdpAssociationHook& hook) noexcept;
    void Stop() noexcept;

private:
    void OnTimeout() noexcept override;
    void Schedule() noexcept;
    void Place(std::size_t index, UdpAssociationHook* hook) noexcept;
    void SiftUp(std::size_t index) noexcept;
    void SiftDown(std::size_t index) noexcept;
    void Repair(std::size_t index) noexcept;

    TimeoutScheduler& scheduler_;
    void* failure_context_ = nullptr;
    FailureCallback on_failure_ = nullptr;
    memory::Vector<UdpAssociationHook*> heap_;
    TimePoint armed_deadline_{};
    bool stopped_ = false;
    bool failed_ = false;
    bool running_batch_ = false;
};

struct UdpHandoffRecord;

class UdpReplySink {
public:
    virtual ~UdpReplySink() noexcept = default;

    [[nodiscard]] virtual bool EnqueueUdpReply(
        UdpIngress& ingress,
        std::string_view socket_key,
        const std::shared_ptr<udp::socket>& sock,
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
    uint32_t worker_id = 0;
    UdpReplySink& reply_sink;
    // Session environment of the listener that received the datagram.
    const app::DatagramSessionEnvironment& environment;
};

// Only authenticated identity and execution ownership metadata live here.
// Protocol continuity state is owned, but never interpreted, by this directory.
struct UdpHandoffIdentity {
    memory::String listener;
    memory::String tag;
    const proxyman::inbound::ProtocolSettings* configuration = nullptr;
    ClientSessionKey client;
    bool operator==(const UdpHandoffIdentity& other) const noexcept {
        return configuration == other.configuration && listener == other.listener &&
            tag == other.tag && client == other.client;
    }
};
struct UdpHandoffIdentityHash {
    size_t operator()(const UdpHandoffIdentity& key) const noexcept {
        auto hash = ClientSessionKeyHash{}(key.client);
        hash ^= std::hash<std::string_view>{}(key.listener) + (hash << 6) + (hash >> 2);
        hash ^= std::hash<std::string_view>{}(key.tag) + (hash << 6) + (hash >> 2);
        return hash ^ std::hash<const proxyman::inbound::ProtocolSettings*>{}(key.configuration);
    }
};
// Worker-private owner for native UDP sockets, client sessions and reply queues.
class UdpIngress final {
public:
    // Handles remain Worker-local; receive/send operations retain them only
    // across their own asynchronous cancellation boundary.
    using SocketPtr = std::shared_ptr<udp::socket>;

    // Owned by the sender frame; descriptors borrow the payload's Buffer blocks,
    // which stay in place when the packet itself moves.
    struct PendingUdpReply {
        uint64_t id = 0;
        udp::endpoint endpoint;
        buf::MultiBuffer payload;
        UdpResourceBudget::PayloadReservation reservation;
        ConstBufferSpanBuilder<buf::MultiBuffer::kInlineCapacity> send_buffers;

        [[nodiscard]] std::span<const net::const_buffer> SendBuffers() const noexcept;
    };
    class ClientSession;
    using ClientSessionPtr = std::shared_ptr<ClientSession>;
    // The native response path has one concrete owner, not an erased callback.
    // sink is Worker-local and outlives all joined session/reply operations.
    struct ReplyRoute {
        memory::String socket_key;
        SocketPtr socket;
        std::shared_ptr<::InboundDatagramResponse> response;
        UdpReplySink* sink = nullptr;
        uint32_t worker_id = 0;
        UdpIngress* owner = nullptr;

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

    [[nodiscard]] static SocketPtr MakeSocket(
        net::io_context& io_context) {
        return std::make_shared<udp::socket>(io_context);
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
        std::chrono::steady_clock::time_point now,
        std::shared_ptr<UdpHandoffRecord> record = {});
    void RegisterNativeJob(const ClientSessionPtr& session);
    void DetachNativeJob(ClientSession& session) noexcept;
    struct BoundSocket {
        SocketPtr socket;
        // Resolved once at attachment; the bound address never changes.
        std::optional<tcp::endpoint> local_endpoint;
        InboundDatagramAssociationIndex associations;
    };
    struct QueuedUdpReply {
        udp::endpoint endpoint;
        buf::MultiBuffer payload;
        size_t payload_size = 0;
        UdpResourceBudget::PayloadReservation reservation;
    };
    struct ReplyQueueState {
        memory::RingDeque<QueuedUdpReply> pending;
        size_t queued_bytes = 0;
        uint64_t active_id = 0;
        size_t active_payload_size = 0;
    };
    struct UdpClientSession {
        ClientSessionPtr link;
        UdpAssociationHook reclaim_hook;
    };
    using UdpClientSessionMap = memory::UnorderedMap<
        ClientSessionKey,
        UdpClientSession,
        ClientSessionKeyHash>;
    using UdpSocketMap = memory::UnorderedMap<
        memory::String,
        BoundSocket,
        TransparentStringHash,
        TransparentStringEq>;
    using ReplyQueueMap = memory::UnorderedMap<
        memory::String,
        ReplyQueueState,
        TransparentStringHash,
        TransparentStringEq>;
    using ClientSessionOuterMap = memory::UnorderedMap<
        memory::String,
        UdpClientSessionMap,
        TransparentStringHash,
        TransparentStringEq>;
    enum class State : uint8_t { Running, Stopping, Drained };

    [[nodiscard]] std::optional<PendingUdpReply> BeginReplySend(ReplyQueueState& queue);
    void Link(UdpClientSession& row, std::string_view socket_key,
              const ClientSessionKey& client_key, std::chrono::seconds idle_timeout) noexcept;
    void SetLocalAssociation(const UdpAssociationHook& hook,
                             InboundDatagramAssociation* association) noexcept;
    void Unlink(UdpClientSession& row) noexcept;

    memory::String tag_;
    std::unique_ptr<::Inbound> proxy_;
    UdpAssociationReclaimer& reclaimer_;
    UdpResourceBudget& budget_;
    UdpSocketMap udp_sockets_;
    ReplyQueueMap reply_queues_;
    ClientSessionOuterMap client_sessions_;
    SignalChannel completion_signal_;
    memory::UnorderedMap<UdpHandoffIdentity, std::shared_ptr<UdpHandoffRecord>,
                                    UdpHandoffIdentityHash> handoff_records_;
    ClientSession* jobs_ = nullptr;
    size_t outstanding_jobs_ = 0;
    size_t join_observers_ = 0;
    uint64_t last_reply_id_ = 0;
    State state_ = State::Running;
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
    net::awaitable<void> WriteBuffers(
        std::span<const net::const_buffer> buffers) override {
        return WriteBuffersAsMultiBuffer(buffers);
    }

private:
    friend class UdpIngress;

    struct RequestData {
        explicit RequestData(routing::DispatchPolicy dispatch_policy)
            : policy(std::move(dispatch_policy)) {}
        session::Context context;
        routing::DispatchPolicy policy;
        routing::Dispatcher* dispatcher = nullptr;
        net::io_context* io_context = nullptr;
        StatsShard* stats = nullptr;
        TimeoutsConfig timeouts;
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
    memory::RingDeque<QueuedInput> input_queue_;
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
};


struct UdpHandoffRecord {
    std::unique_ptr<InboundDatagramAssociation> association;
    std::weak_ptr<UdpIngress::ClientSession> session;
    std::shared_ptr<const proxyman::inbound::ProtocolSettings> configuration;
    explicit UdpHandoffRecord(const InboundDatagramAssociationPolicy& policy)
        : association(policy.create()) {}
};
class UdpHandoffDirectory final {
public:
    UdpHandoffDirectory() = default;

    // Worker-local directory. A tombstone is retained after its live
    // association ends until the entire timestamp/replay protection expires.
    static std::shared_ptr<UdpHandoffRecord> Claim(
        memory::UnorderedMap<UdpHandoffIdentity, std::shared_ptr<UdpHandoffRecord>,
                                        UdpHandoffIdentityHash>& records,
        const UdpHandoffIdentity& key,
        std::shared_ptr<const proxyman::inbound::ProtocolSettings> configuration,
        const InboundDatagramAssociationPolicy& policy) {
        using Clock = InboundDatagramAssociation::Clock;
        if (auto found = records.find(key); found != records.end()) {
            if (&found->second->association->Policy() != &policy ||
                std::exchange(found->second->association->claimed, true))
                return {};
            const auto protected_until = found->second->association->ProtectedUntil();
            if (found->second->session.expired() &&
                protected_until != Clock::time_point{} &&
                protected_until < Clock::now()) {
                try {
                    auto record = std::make_shared<UdpHandoffRecord>(policy);
                    record->configuration = std::move(configuration);
                    found->second = std::move(record);
                } catch (...) {
                    found->second->association->claimed = false;
                    throw;
                }
            }
            return found->second;
        }
        if (records.size() >= policy.capacity) {
            const auto now = std::chrono::steady_clock::now();
            for (auto it = records.begin(); it != records.end();) {
                const auto& row = *it->second;
                if (!row.association->claimed &&
                    row.session.expired() && row.association->ProtectedUntil() < now)
                    it = records.erase(it);
                else ++it;
            }
            MaybeShrinkHashContainer(records);
            if (records.size() >= policy.capacity) return {};
        }
        auto record = std::make_shared<UdpHandoffRecord>(policy);
        record->configuration = std::move(configuration);
        records.emplace(key, record);
        return record;
    }

    std::shared_ptr<UdpHandoffRecord> Claim(
        const UdpHandoffIdentity& key,
        std::shared_ptr<const proxyman::inbound::ProtocolSettings> configuration,
        const InboundDatagramAssociationPolicy& policy) {
        return Claim(records_, key, std::move(configuration), policy);
    }

private:
    memory::UnorderedMap<UdpHandoffIdentity, std::shared_ptr<UdpHandoffRecord>,
                                    UdpHandoffIdentityHash> records_;
};
}  // namespace worker_detail
