#pragma once

#include "hysteria_protocol.hpp"
#include "quic_stream.hpp"
#include "app/proxyman/inbound/prepared_config.hpp"
#include "app/session_capabilities.hpp"
#include "app/rate_limiter.hpp"
#include "common/allocator.hpp"
#include "common/buf/multi_buffer.hpp"
#include "common/session.hpp"
#include "common/sharded_user_stats.hpp"
#include "common/asio_types.hpp"
#include "common/string_hash.hpp"

#include <asio/steady_timer.hpp>
#include <openssl/ssl.h>
#include <nghttp3/nghttp3.h>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <linux/filter.h>
#include <sys/socket.h>

#include <algorithm>
#include <array>
#include <cstdint>
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

// Prepared Hysteria settings, built by the proxy registration on the cold
// path. The QUIC transport selects ALPN/auth/framing by version and announces
// the bandwidth; the inbound handler reads the request format by version.
class Settings final : public proxyman::inbound::ProtocolSettings {
public:
    Version version = Version::V2;
    uint64_t upload_bytes_per_second = 0;
    uint64_t download_bytes_per_second = 0;
};

[[nodiscard]] inline const Settings* GetSettings(
    const proxyman::inbound::BuildRequest& request) noexcept {
    return dynamic_cast<const Settings*>(request.settings.get());
}

inline constexpr size_t kServerConnectionIdLength = 18;
inline constexpr uint8_t kServerCidMagic0 = 0xa5;
inline constexpr uint8_t kServerCidMagic1 = 0x5a;
inline constexpr uint16_t kServerCidMagicWord =
    (static_cast<uint16_t>(kServerCidMagic0) << 8) | kServerCidMagic1;

inline void EncodeWorkerServerCid(ngtcp2_cid& cid, size_t length, uint32_t worker_id) noexcept {
    cid.datalen = length;
    if (length >= 3) {
        cid.data[0] = kServerCidMagic0;
        cid.data[1] = kServerCidMagic1;
        cid.data[2] = static_cast<uint8_t>(worker_id);
    }
}

[[nodiscard]] inline bool AttachQuicReuseportBpf(int fd, uint32_t worker_count) noexcept {
    const uint32_t count = std::max<uint32_t>(1, worker_count);
    // Fallback hashes Initial DCID[0..3] at payload[6..9] for uniform distribution.
    std::array<sock_filter, 15> insns{{
        // 0: A = payload[0] (QUIC Header flags)
        {BPF_LD | BPF_B | BPF_ABS, 0, 0, 0},
        // 1: if (A & 0x80) != 0 goto 6 (Long Header)
        {BPF_JMP | BPF_JSET | BPF_K, 4, 0, 0x80},
        // 2: Short Header: A = payload[1..2] (DCID[0..1])
        {BPF_LD | BPF_H | BPF_ABS, 0, 0, 1},
        // 3: if A != kServerCidMagicWord goto 12 (fallback hash)
        {BPF_JMP | BPF_JEQ | BPF_K, 0, 8, kServerCidMagicWord},
        // 4: A = payload[3] (DCID[2] == worker_id)
        {BPF_LD | BPF_B | BPF_ABS, 0, 0, 3},
        // 5: jump to 11 (range check)
        {BPF_JMP | BPF_JA, 0, 0, 5},
        // 6: Long Header: A = payload[5] (DCID length)
        {BPF_LD | BPF_B | BPF_ABS, 0, 0, 5},
        // 7: if A != kServerConnectionIdLength goto 12 (fallback hash)
        {BPF_JMP | BPF_JEQ | BPF_K, 0, 4, static_cast<uint32_t>(kServerConnectionIdLength)},
        // 8: A = payload[6..7] (Long Header DCID[0..1])
        {BPF_LD | BPF_H | BPF_ABS, 0, 0, 6},
        // 9: if A != kServerCidMagicWord goto 12 (fallback hash)
        {BPF_JMP | BPF_JEQ | BPF_K, 0, 2, kServerCidMagicWord},
        // 10: A = payload[8] (Long Header DCID[2] == worker_id)
        {BPF_LD | BPF_B | BPF_ABS, 0, 0, 8},
        // 11: if A >= count goto 12 (fallback hash) else goto 14 (return A)
        {BPF_JMP | BPF_JGE | BPF_K, 0, 2, count},
        // 12: fallback: A = payload[6..9] (Initial random DCID prefix)
        {BPF_LD | BPF_W | BPF_ABS, 0, 0, 6},
        // 13: A = A % count
        {BPF_ALU | BPF_MOD | BPF_K, 0, 0, count},
        // 14: return A
        {BPF_RET | BPF_A, 0, 0, 0},
    }};
    sock_fprog prog{
        .len = static_cast<unsigned short>(insns.size()),
        .filter = insns.data(),
    };
    return ::setsockopt(fd, SOL_SOCKET, SO_ATTACH_REUSEPORT_CBPF, &prog, sizeof(prog)) == 0;
}

struct ConnectionId {
    std::array<uint8_t, NGTCP2_MAX_CIDLEN> bytes{};
    uint8_t size = 0;
    explicit ConnectionId(const ngtcp2_cid& cid) noexcept
        : ConnectionId(cid.data, cid.datalen) {}
    ConnectionId(const uint8_t* data, size_t length) noexcept
        : size(static_cast<uint8_t>(length)) {
        std::copy_n(data, length, bytes.begin());
    }
    bool operator==(const ConnectionId&) const noexcept = default;
};

struct ConnectionIdHash {
    size_t operator()(const ConnectionId& id) const noexcept {
        size_t hash = 1469598103934665603ULL;
        for (size_t i = 0; i < id.size; ++i) {
            hash ^= id.bytes[i];
            hash *= 1099511628211ULL;
        }
        return hash ^ id.size;
    }
};

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

// One accepted Hysteria QUIC connection: ngtcp2/nghttp3 state, connection
// level authentication, request streams and UDP sessions. Owned by its
// listener's CID map and by its own coroutines; delivered streams and
// sessions hold it weakly because a dispatched request may outlive it.
class Connection final : public std::enable_shared_from_this<Connection> {
public:
    static std::shared_ptr<Connection> Create(
        HysteriaIngress& listener, SocketState& socket,
        const udp::endpoint& remote, const ngtcp2_pkt_hd& header);

    ~Connection() noexcept { Close(); }

    Connection(const Connection&) = delete;
    Connection& operator=(const Connection&) = delete;

    bool Feed(SocketState& socket, const udp::endpoint& remote,
              std::span<const uint8_t> packet, bool flush = true);
    void OnExpiry();
    [[nodiscard]] ngtcp2_tstamp Expiry() const noexcept {
        return std::min(fragment_expiry_,
            core_ && core_->quic ? ngtcp2_conn_get_expiry(core_->quic)
                                : std::numeric_limits<ngtcp2_tstamp>::max());
    }
    [[nodiscard]] bool Closed() const noexcept { return closed_; }
    void Close() noexcept;
    [[nodiscard]] net::io_context& Reactor() const noexcept;
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
    friend class HysteriaIngress;
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
        Core() = default;
        ~Core() {
            if (quic) ngtcp2_conn_del(quic);
            if (http) nghttp3_conn_del(http);
            if (ssl) SSL_free(ssl);
        }
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
        struct PendingInputPacket {
            std::shared_ptr<SocketState> socket;
            udp::endpoint remote;
            memory::ThreadLocalVector<uint8_t> bytes;
        };
        memory::ThreadLocalDeque<PendingInputPacket> inbox;
        size_t inbox_bytes = 0;
        bool pump_scheduled = false;
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

    Connection(HysteriaIngress& listener, SocketState& socket, const udp::endpoint& remote);

    static ngtcp2_conn* GetConn(ngtcp2_crypto_conn_ref* ref) {
        return static_cast<Connection*>(ref->user_data)->core_->quic;
    }

    bool Initialize(const ngtcp2_pkt_hd& header);
    net::awaitable<void> Run();
    net::awaitable<void> WaitClosed();
    SocketState* OutputSocket(const ngtcp2_path& path) const noexcept;
    void PublishExpiry() noexcept;
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

    HysteriaIngress* listener_;
    memory::ThreadLocalVector<ConnectionId> connection_ids_;
    AwaitableTaskGroup* tasks_ = nullptr;
    SignalChannel closed_signal_;
    std::optional<Core> core_;
    session::Context base_context_;
    SignalChannel physical_ready_;
    ConnectionLimiter::Reservation physical_reservation_;
    std::optional<UserOnlineSessionGuard> online_session_;
    std::shared_ptr<InboundTransportStreamHandler> stream_sink_;
    memory::ThreadLocalUnorderedMap<uint64_t, PendingFragments> fragments_;
    // 续期或删除后允许保留较早的唤醒；到期时重算，避免逐片扫描。
    ngtcp2_tstamp fragment_expiry_ = std::numeric_limits<ngtcp2_tstamp>::max();
    ngtcp2_tstamp expiry_ = std::numeric_limits<ngtcp2_tstamp>::max();
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
