#pragma once

#include "hysteria_protocol.hpp"
#include "quic_memory.hpp"
#include "quic_stream.hpp"
#include "quic_handoff.hpp"
#include "app/session_capabilities.hpp"

#include "app/rate_limiter.hpp"
#include "common/allocator.hpp"
#include "common/asio_types.hpp"
#include "common/buf/multi_buffer.hpp"
#include "common/session.hpp"
#include "common/sharded_user_stats.hpp"

#include <nghttp3/nghttp3.h>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <openssl/ssl.h>

#include <algorithm>
#include <array>
#include <bitset>
#include <limits>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>

class InboundTransportStreamHandler;
class AwaitableTaskGroup;

namespace transport::internet::hysteria {

class QuicListener;
struct SocketState;

// One accepted Hysteria QUIC connection: ngtcp2/nghttp3 state, connection
// level authentication, request streams and UDP sessions. Owned by its
// listener's CID map and by its own coroutines; delivered streams and
// sessions hold it weakly because a dispatched request may outlive it.
class Connection final : public std::enable_shared_from_this<Connection>,
                         public ExecutionDomain::NativeResource {
public:
    static std::shared_ptr<Connection> Create(
        QuicListener& listener, SocketState& socket,
        const udp::endpoint& remote, const ngtcp2_pkt_hd& header);

    ~Connection() noexcept {
        memory::ScopedAllocationDomain scope(capabilities_->Allocation());
        Close();
        fragments_ = {};
        connection_ids_ = {};
        core_.reset();
        base_context_.inbound = session::Inbound(memory::worker_pool_resource());
        base_context_.content = session::Content(memory::worker_pool_resource());
    }

    Connection(const Connection&) = delete;
    Connection& operator=(const Connection&) = delete;

    bool Feed(SocketState& socket, const udp::endpoint& remote,
              std::span<const uint8_t> packet);
    void OnExpiry();
    [[nodiscard]] ngtcp2_tstamp Expiry() const noexcept {
        return std::min(fragment_expiry_,
            core_ && core_->quic ? ngtcp2_conn_get_expiry(core_->quic)
                                : std::numeric_limits<ngtcp2_tstamp>::max());
    }
    [[nodiscard]] bool Closed() const noexcept { return closed_; }
    void Close() noexcept;
    [[nodiscard]] const std::shared_ptr<QuicOwnership>& Ownership() const noexcept { return ownership_; }
    [[nodiscard]] net::any_io_executor Executor() const { return ownership_->domain->Executor(); }
    [[nodiscard]] net::io_context& Reactor() const noexcept { return ownership_->domain->Reactor(); }
    net::awaitable<void> PrepareHandoff(const ExecutionDomain::HandoffTarget&) override;
    void CommitHandoff(const ExecutionDomain::HandoffTarget&) noexcept override;
    net::awaitable<void> CancelHandoff(const ExecutionDomain::HandoffTarget&) override;
    void BeginValidation(QuicListener& target, const udp::endpoint& local,
                         const udp::endpoint& remote);
    [[nodiscard]] bool ValidationSucceeded() const noexcept { return validation_succeeded_; }
    [[nodiscard]] bool Authenticated() const noexcept { return authenticated_; }
    void EndValidation(bool committed) noexcept;

    // Physical admission starts when the connection is accepted and resolves
    // before any credential is evaluated, as on the TCP path.
    net::awaitable<void> ReservePhysicalAdmission();

    // Request stream and UDP session operations.
    net::awaitable<void> WriteStream(int64_t stream_id, buf::MultiBuffer payload);
    void ConsumeStream(int64_t stream_id, size_t bytes) noexcept;
    void ShutdownStreamWrite(int64_t stream_id) noexcept;
    void CancelStream(int64_t stream_id) noexcept;
    [[nodiscard]] bool SendUdpMessage(uint32_t session_id, const TargetAddress& target,
                                      std::span<const uint8_t> payload);
    void CloseUdpSession(uint32_t session_id) noexcept;

private:
    friend class QuicListener;
    struct H3Request {
        memory::ThreadLocalString method;
        memory::ThreadLocalString path;
        memory::ThreadLocalString authority;
        memory::ThreadLocalString auth;
    };
    struct StreamRecord {
        explicit StreamRecord(std::shared_ptr<QuicStreamState> state_value)
            : state(std::move(state_value)) {}
        std::shared_ptr<QuicStreamState> state;
        memory::ThreadLocalDeque<buf::MultiBuffer> output;
        size_t queued_bytes = 0;
        size_t output_offset = 0;
        uint64_t acknowledged = 0;
        memory::ThreadLocalMap<uint64_t, uint64_t> acked_ranges;
        bool fin_pending = false;
        bool flow_blocked = false;
        // A Hysteria request stream rather than an HTTP/3 or v1 control stream.
        bool raw = false;
        // Handed to the inbound handler, or consumed as a v1 UDP-session open.
        bool delivered = false;
    };
    struct Core {
        explicit Core(memory::AllocationDomain& domain)
            : memory(domain) {}
        ~Core() {
            if (quic) ngtcp2_conn_del(quic);
            if (http) nghttp3_conn_del(http);
            if (ssl) SSL_free(ssl);
        }
        QuicMemory memory;
        ngtcp2_conn* quic = nullptr;
        nghttp3_conn* http = nullptr;
        SSL* ssl = nullptr;
        ngtcp2_crypto_conn_ref conn_ref{};
        // Stable for every ngtcp2 path copy, including fallback/history.
        struct PathBinding {} path_binding;
        udp::endpoint local;
        udp::endpoint remote;
        ngtcp2_cid server_cid{};
        memory::ThreadLocalUnorderedMap<int64_t, StreamRecord> streams;
        // IDs, not iterators, survive stream retirement during packet writes.
        int64_t next_output_stream = -1;
        memory::ThreadLocalUnorderedMap<int64_t, H3Request> h3_requests;
        memory::ThreadLocalDeque<memory::ByteVector> datagrams;
        // Registered sessions; each unregisters itself on destruction and is
        // detached here first when the connection closes.
        memory::ThreadLocalUnorderedMap<uint32_t, UdpSessionStream*> udp_sessions;
    };
    struct PendingFragments {
        TargetAddress target;
        memory::ThreadLocalVector<memory::ByteVector> payloads;
        // One-based indices into arrived nonempty payloads; zero carries no bytes.
        std::array<uint8_t, 256> payload_slots{};
        std::bitset<256> received_fragments;
        uint8_t count = 0;
        uint8_t received = 0;
        size_t bytes = 0;
        ngtcp2_tstamp deadline = 0;
        ngtcp2_tstamp expires_at = 0;
    };
    enum class PhysicalAdmission : uint8_t { Pending, Admitted, Rejected };
    enum class AdmitResult : uint8_t { Admitted, AuthFailed, Limited, DeviceLimited };

    Connection(QuicListener& listener, SocketState& socket, const udp::endpoint& remote);

    static ngtcp2_conn* GetConn(ngtcp2_crypto_conn_ref* ref) {
        return static_cast<Connection*>(ref->user_data)->core_->quic;
    }

    bool Initialize(const ngtcp2_pkt_hd& header);
    net::awaitable<void> Run(ngtcp2_pkt_hd header);
    net::awaitable<void> WaitClosed();
    SocketState* OutputSocket(const ngtcp2_path& path) const noexcept;
    void PublishExpiry() noexcept;
    [[nodiscard]] bool CandidateSelected() const noexcept;
    [[nodiscard]] bool CandidateValidationPending() const noexcept { return validation_pending_; }
    void InitializeBaseContext(const udp::endpoint& remote);
    void Flush();
    void Refuse() noexcept;
    void SpawnOwned(net::awaitable<void> task);
    void OnStreamData(uint32_t flags, int64_t stream_id,
                      std::span<const uint8_t> data);
    void StartRawStream(int64_t stream_id, StreamRecord& stream);
    void OpenV1UdpSession(int64_t stream_id, StreamRecord& stream, size_t header_bytes);
    net::awaitable<void> DeliverStream(std::unique_ptr<AsyncStream> stream);
    net::awaitable<AdmitResult> AdmitConnection(std::string_view credential);
    net::awaitable<void> RunV1Control(int64_t stream_id);
    net::awaitable<void> AuthenticateV2(int64_t stream_id);
    bool SetupHttp3();
    void SubmitHttpStatus(int64_t stream_id, std::string_view status,
                          bool authenticated);
    void OnHttpHeader(int64_t stream_id, int32_t token,
                      nghttp3_rcbuf* name, nghttp3_rcbuf* value);
    void HandleUdpMessage(const UdpMessage& message);
    void ExpireUdpFragments(ngtcp2_tstamp now) noexcept;
    void DeliverUdpPacket(uint32_t session_id, const TargetAddress& target,
                          std::span<const uint8_t> payload);

    static int ReceiveStreamData(ngtcp2_conn*, uint32_t flags, int64_t stream_id,
        uint64_t, const uint8_t* data, size_t length, void* user_data, void*) {
        static_cast<Connection*>(user_data)->OnStreamData(
            flags, stream_id, {data, length});
        return 0;
    }
    static int AckStreamData(ngtcp2_conn*, int64_t stream_id, uint64_t offset,
        uint64_t length, void* user_data, void*);
    static int OpenStream(ngtcp2_conn*, int64_t stream_id, void* user_data);
    static int CloseStream(ngtcp2_conn* conn, uint32_t flags, int64_t stream_id,
        uint64_t, void* user_data, void*);
    static int ResetStream(ngtcp2_conn* conn, int64_t stream_id, uint64_t,
        uint64_t, void* user_data, void*);
    static int StopSending(ngtcp2_conn* conn, int64_t stream_id, uint64_t,
        void* user_data, void*);
    static void Random(uint8_t* data, size_t length, const ngtcp2_rand_ctx*);
    static int NewConnectionId(ngtcp2_conn*, ngtcp2_cid* cid, uint8_t* token,
        size_t length, void* user_data);
    static int RemoveConnectionId(ngtcp2_conn*, const ngtcp2_cid* cid,
        void* user_data);
    static int UpdateKey(ngtcp2_conn* conn, uint8_t* rx_secret,
        uint8_t* tx_secret, ngtcp2_crypto_aead_ctx* rx_ctx, uint8_t* rx_iv,
        ngtcp2_crypto_aead_ctx* tx_ctx, uint8_t* tx_iv,
        const uint8_t* current_rx, const uint8_t* current_tx, size_t secret_length,
        void*);
    static int ExtendMaxStreams(ngtcp2_conn*, uint64_t maximum, void* user_data) {
        auto& self = *static_cast<Connection*>(user_data);
        if (self.core_->http)
            nghttp3_conn_set_max_client_streams_bidi(self.core_->http, maximum);
        return 0;
    }
    static int ExtendMaxStreamData(ngtcp2_conn*, int64_t stream_id, uint64_t,
        void* user_data, void*) {
        auto& self = *static_cast<Connection*>(user_data);
        if (auto it = self.core_->streams.find(stream_id);
            it != self.core_->streams.end())
            it->second.flow_blocked = false;
        return self.core_->http
            ? nghttp3_conn_unblock_stream(self.core_->http, stream_id) : 0;
    }
    static int ReceiveTxKey(ngtcp2_conn*, ngtcp2_encryption_level level,
        void* user_data);
    static int ReceiveDatagram(ngtcp2_conn*, uint32_t flags,
        const uint8_t* data, size_t length, void* user_data);
    static int PathValidationStarted(ngtcp2_conn*, uint32_t,
        const ngtcp2_path*, const ngtcp2_path*, void*);
    static int PathValidated(ngtcp2_conn*, uint32_t, const ngtcp2_path*,
        const ngtcp2_path*, ngtcp2_path_validation_result, void*);

    QuicListener* listener_;
    QuicListener* validation_listener_ = nullptr;
    std::shared_ptr<app::PhysicalSessionCapabilities> capabilities_;
    std::shared_ptr<QuicOwnership> ownership_;
    memory::ThreadLocalVector<ConnectionId> connection_ids_;
    std::unique_ptr<QuicDirectory::Retirement> retirement_;
    std::shared_ptr<app::PhysicalSessionRegistry> registry_;
    std::shared_ptr<app::PhysicalSessionRecord> registry_record_;
    AwaitableTaskGroup* tasks_ = nullptr;
    SignalChannel closed_signal_;
    udp::endpoint candidate_local_;
    udp::endpoint candidate_remote_;
    ngtcp2_path_storage validation_original_path_{};
    bool validating_ = false;
    bool validation_succeeded_ = false;
    bool validation_reused_ = false;
    bool validation_authenticated_ = false;
    bool validation_pending_ = false;
    bool resource_registered_ = false;
    std::unique_ptr<Core> core_;
    session::Context base_context_;
    SignalChannel physical_ready_;
    ConnectionLimiter::Reservation physical_reservation_;
    std::optional<UserOnlineSessionGuard> online_session_;
    std::shared_ptr<InboundTransportStreamHandler> stream_sink_;
    memory::ThreadLocalUnorderedMap<uint64_t, PendingFragments> fragments_;
    // 续期或删除后允许保留较早的唤醒；到期时重算，避免逐片扫描。
    ngtcp2_tstamp fragment_expiry_ = std::numeric_limits<ngtcp2_tstamp>::max();
    uint32_t next_udp_session_id_ = 1;
    uint16_t next_udp_packet_id_ = 0;
    PhysicalAdmission physical_ = PhysicalAdmission::Pending;
    bool admitting_ = false;
    bool authenticated_ = false;
    bool stats_open_ = false;
    bool in_ngtcp2_callback_ = false;
    bool closed_ = false;
};

}  // namespace transport::internet::hysteria
