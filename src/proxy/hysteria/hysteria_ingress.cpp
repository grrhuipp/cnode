#include "hysteria_ingress.hpp"

#include "hysteria_protocol.hpp"
#include "hysteria_settings.hpp"
#include "quic_memory.hpp"
#include "quic_stream.hpp"
#include "acppnode/app/proxyman/inbound/user_store.hpp"

#include "acppnode/app/rate_limiter.hpp"
#include "acppnode/app/stats.hpp"
#include "acppnode/common/buf/multi_buffer.hpp"
#include "acppnode/common/ip_utils.hpp"
#include "acppnode/common/session.hpp"
#include "acppnode/common/sharded_user_stats.hpp"
#include "acppnode/common/string_hash.hpp"
#include "acppnode/features/routing/dispatcher.hpp"
#include "acppnode/infra/config_types.hpp"
#include "acppnode/infra/log.hpp"
#include "../../transport/internet/tls_client_context.hpp"
#include "../inbound_admission.hpp"

#include <nghttp3/nghttp3.h>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_boringssl.h>

#include <openssl/rand.h>
#include <openssl/ssl.h>

#include <asio/as_tuple.hpp>
#include <asio/co_spawn.hpp>
#include <asio/steady_timer.hpp>
#include <asio/use_awaitable.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <deque>
#include <limits>
#include <unordered_map>
#include <utility>

namespace acpp::proxy::hysteria {
namespace {

constexpr size_t kServerConnectionIdLength = 18;
constexpr size_t kMaxPacketSize = 64 * 1024;
constexpr size_t kMaxQueuedSocketPackets = 1024;
constexpr size_t kMaxStreamHeaderBytes = 8192;
constexpr uint64_t kMaxConnectionData = 16 * 1024 * 1024;
constexpr uint64_t kMaxStreamData = 4 * 1024 * 1024;
constexpr uint64_t kMaxStreams = 1024;

[[nodiscard]] ngtcp2_tstamp Timestamp() noexcept {
    return static_cast<ngtcp2_tstamp>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
}

struct ConnectionId {
    std::array<uint8_t, NGTCP2_MAX_CIDLEN> bytes{};
    uint8_t size = 0;

    explicit ConnectionId(const ngtcp2_cid& cid) noexcept
        : size(static_cast<uint8_t>(cid.datalen)) {
        std::copy_n(cid.data, cid.datalen, bytes.begin());
    }
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

struct SslContextDeleter {
    void operator()(SSL_CTX* context) const noexcept { SSL_CTX_free(context); }
};
using SharedSslContext = std::shared_ptr<SSL_CTX>;

int SelectAlpn(SSL*, const uint8_t** out, uint8_t* outlen,
               const uint8_t* input, unsigned input_length, void* argument) {
    const auto expected = *static_cast<const std::string_view*>(argument);
    const uint8_t* current = input;
    const uint8_t* end = input + input_length;
    while (current < end) {
        const size_t length = *current++;
        if (static_cast<size_t>(end - current) < length) return SSL_TLSEXT_ERR_ALERT_FATAL;
        if (length == expected.size() &&
            std::memcmp(current, expected.data(), length) == 0) {
            *out = current;
            *outlen = static_cast<uint8_t>(length);
            return SSL_TLSEXT_ERR_OK;
        }
        current += length;
    }
    return SSL_TLSEXT_ERR_ALERT_FATAL;
}

[[nodiscard]] SharedSslContext BuildSslContext(
    const StreamSettings& stream_settings, Version version) {
    if (!stream_settings.IsTls() || !stream_settings.tls.pem ||
        !stream_settings.tls.HasCertificatePair()) {
        LOG_ERROR("Hysteria requires a prepared TLS certificate and private key");
        return {};
    }
    std::unique_ptr<SSL_CTX, SslContextDeleter> context{
        SSL_CTX_new(TLS_server_method())};
    if (!context ||
        ngtcp2_crypto_boringssl_configure_server_context(context.get()) != 0 ||
        !ConfigureTlsCertificatePem(
            context.get(), *stream_settings.tls.pem)) {
        LOG_ERROR("failed to build Hysteria QUIC TLS context");
        return {};
    }
    SSL_CTX_set_min_proto_version(context.get(), TLS1_3_VERSION);
    SSL_CTX_set_mode(context.get(), SSL_MODE_RELEASE_BUFFERS);
    static constexpr std::string_view kV1Alpn = "hysteria";
    static constexpr std::string_view kV2Alpn = "h3";
    auto* alpn = const_cast<std::string_view*>(
        version == Version::V1 ? &kV1Alpn : &kV2Alpn);
    SSL_CTX_set_alpn_select_cb(context.get(), &SelectAlpn, alpn);
    return SharedSslContext(context.release(), SslContextDeleter{});
}

[[nodiscard]] ngtcp2_addr MakeAddress(const udp::endpoint& endpoint) noexcept {
    return ngtcp2_addr{
        const_cast<sockaddr*>(endpoint.data()),
        static_cast<socklen_t>(endpoint.size())};
}
[[nodiscard]] std::optional<udp::endpoint> EndpointFromAddress(
    const ngtcp2_addr& address) {
    if (!address.addr) return std::nullopt;
    const auto family = address.addr->sa_family;
    const size_t expected = family == AF_INET ? sizeof(sockaddr_in)
        : family == AF_INET6 ? sizeof(sockaddr_in6) : 0;
    if (expected == 0 || address.addrlen != expected) return std::nullopt;
    udp::endpoint endpoint;
    std::memcpy(endpoint.data(), address.addr, expected);
    endpoint.resize(expected);
    return endpoint;
}


class Connection;

struct SocketState final : memory::ThreadAllocated {
    explicit SocketState(net::io_context& io) : changed(io, 1) {}
    HysteriaIngress::SocketPtr socket;
    memory::ThreadLocalString key;
    udp::endpoint local;
    std::array<uint8_t, kMaxPacketSize> receive_buffer{};
    udp::endpoint remote;
    struct Output {
        std::vector<uint8_t> data;
        udp::endpoint remote;
    };
    memory::ThreadLocalDeque<Output> output;
    SignalChannel changed;
};


class HysteriaUdpLink final
    : public transport::MultiBufferReader
    , public transport::MultiBufferWriter
    , public memory::ThreadAllocated {
public:
    using Sender = std::function<bool(
        const TargetAddress&, std::span<const uint8_t>)>;

    HysteriaUdpLink(net::io_context& io, Sender sender)
        : signal_(io, 1), sender_(std::move(sender)) {}

    bool Push(const TargetAddress& target, std::span<const uint8_t> payload) {
        if (closed_ || payload.empty() ||
            queued_bytes_ > 512 * 1024 - payload.size()) return false;
        buf::MultiBuffer packet;
        if (!buf::AppendSpanToMultiBuffer(payload, packet)) return false;
        for (auto* buffer : packet) buffer->SetUDP(target);
        queued_bytes_ += payload.size();
        input_.push_back(std::move(packet));
        (void)signal_.try_send(IoErrorCode{});
        return true;
    }

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
        while (input_.empty()) {
            if (closed_) co_return buf::MultiBuffer{};
            auto [error] = co_await signal_.async_receive(
                net::as_tuple(net::use_awaitable));
            if (error && closed_) co_return buf::MultiBuffer{};
        }
        auto packet = std::move(input_.front());
        input_.pop_front();
        queued_bytes_ -= std::min(queued_bytes_, packet.byte_size());
        co_return packet;
    }

    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer packet) override {
        if (closed_ || packet.empty()) co_return;
        const TargetAddress* target = nullptr;
        size_t size = 0;
        for (const auto* buffer : packet) {
            if (!buffer || buffer->IsEmpty() || !buffer->HasUDP()) continue;
            if (!target) target = &buffer->UDP();
            else if (!target->SameEndpoint(buffer->UDP()))
                throw transport::LinkError(ErrorCode::PROTOCOL_INVALID_ADDRESS);
            size += buffer->Len();
        }
        if (!target || size == 0 || size > kMaxUdpPayloadLength)
            throw transport::LinkError(ErrorCode::PROTOCOL_INVALID_ADDRESS);
        std::vector<uint8_t> payload;
        payload.reserve(size);
        for (const auto* buffer : packet) {
            if (!buffer || buffer->IsEmpty()) continue;
            auto bytes = buffer->Bytes();
            payload.insert(payload.end(), bytes.begin(), bytes.end());
        }
        if (!sender_(*target, payload))
            throw transport::LinkError(ErrorCode::RESOURCE_EXHAUSTED);
    }

    transport::CancellationSource& Cancellation() noexcept override {
        return cancellation_;
    }
    void Close() noexcept {
        if (closed_) return;
        closed_ = true;
        input_.clear();
        cancellation_.Stop(ErrorCode::CANCELLED);
        (void)signal_.try_send(IoErrorCode{});
    }

private:
    SignalChannel signal_;
    Sender sender_;
    transport::CancellationSource cancellation_;
    memory::ThreadLocalDeque<buf::MultiBuffer> input_;
    size_t queued_bytes_ = 0;
    bool closed_ = false;
};

class Connection final
    : public QuicStreamOwner
    , public std::enable_shared_from_this<Connection> {
public:
    using Spawn = std::function<void(net::awaitable<void>)>;
    using Associate = std::function<void(const ngtcp2_cid&, std::shared_ptr<Connection>)>;
    using Dissociate = std::function<void(const ngtcp2_cid&)>;
    using QueuePacket = std::function<bool(SocketState&, std::vector<uint8_t>, udp::endpoint)>;

    static std::shared_ptr<Connection> Create(
        uint32_t worker_id, net::io_context& io, routing::Dispatcher& dispatcher,
        StatsShard& stats, std::shared_ptr<ConnectionLimiter> limiter,
        UserOnlineTracker& online_tracker, const TimeoutsConfig& timeouts,
        const proxyman::inbound::ReceiverSettings& receiver,
        const Settings& settings, SharedSslContext ssl_context,
        SocketState& socket, const udp::endpoint& remote,
        const ngtcp2_pkt_hd& header, Spawn spawn, Associate associate,
        Dissociate dissociate, QueuePacket queue_packet) {
        auto connection = std::shared_ptr<Connection>(new Connection(
            worker_id, io, dispatcher, stats, std::move(limiter), online_tracker,
            timeouts, receiver, settings, std::move(ssl_context), socket, remote,
            std::move(spawn), std::move(associate), std::move(dissociate),
            std::move(queue_packet)));
        if (!connection->Initialize(header)) return {};
        connection->associate_(
            connection->core_->server_cid, connection);
        return connection;
    }

    ~Connection() noexcept override {
        Close();
        core_.reset();
    }

    bool Feed(SocketState& socket, const udp::endpoint& remote,
              std::span<const uint8_t> packet) {
        if (!core_ || closed_) return false;
        auto local_addr = MakeAddress(socket.local);
        auto remote_addr = MakeAddress(remote);
        ngtcp2_path path{local_addr, remote_addr, &socket};
        ngtcp2_pkt_info packet_info{};
        in_ngtcp2_callback_ = true;
        const int result = ngtcp2_conn_read_pkt(
            core_->quic, &path, &packet_info, packet.data(), packet.size(), Timestamp());
        in_ngtcp2_callback_ = false;
        if (result != 0) {
            if (result != NGTCP2_ERR_DRAINING && result != NGTCP2_ERR_IDLE_CLOSE)
                stats_.OnError();
            Close();
            return false;
        }
        Flush();
        return !closed_;
    }

    void OnExpiry() {
        if (!core_ || closed_) return;
        in_ngtcp2_callback_ = true;
        const int result = ngtcp2_conn_handle_expiry(core_->quic, Timestamp());
        in_ngtcp2_callback_ = false;
        if (result != 0) {
            Close();
            return;
        }
        Flush();
    }

    [[nodiscard]] ngtcp2_tstamp Expiry() const noexcept {
        return core_ && core_->quic ? ngtcp2_conn_get_expiry(core_->quic)
                                    : std::numeric_limits<ngtcp2_tstamp>::max();
    }
    [[nodiscard]] bool Closed() const noexcept { return closed_; }

    net::awaitable<void> WriteStream(
        int64_t stream_id, buf::MultiBuffer payload) override {
        auto it = core_->streams.find(stream_id);
        if (closed_ || it == core_->streams.end()) {
            payload.clear();
            throw transport::LinkError(ErrorCode::CONNECTION_CLOSED);
        }
        const size_t bytes = payload.byte_size();
        if (bytes > 512 * 1024 || it->second.queued_bytes > 512 * 1024 - bytes) {
            payload.clear();
            throw transport::LinkError(ErrorCode::RESOURCE_EXHAUSTED);
        }
        it->second.queued_bytes += bytes;
        it->second.output.push_back(std::move(payload));
        Flush();
        co_return;
    }

    void ConsumeStream(int64_t stream_id, size_t bytes) noexcept override {
        if (!core_ || closed_) return;
        ngtcp2_conn_extend_max_stream_offset(core_->quic, stream_id, bytes);
        ngtcp2_conn_extend_max_offset(core_->quic, bytes);
        Flush();
    }

    void ShutdownStreamWrite(int64_t stream_id) noexcept override {
        if (!core_ || closed_) return;
        auto it = core_->streams.find(stream_id);
        if (it == core_->streams.end()) return;
        it->second.fin_pending = true;
        Flush();
    }

    void CancelStream(int64_t stream_id) noexcept override {
        if (!core_ || closed_) return;
        ngtcp2_conn_shutdown_stream(core_->quic, 0, stream_id, 0);
        Flush();
    }

private:
    struct H3Request {
        std::string method;
        std::string path;
        std::string authority;
        std::string auth;
    };
    struct StreamRecord {
        explicit StreamRecord(std::shared_ptr<QuicStreamState> state_value)
            : state(std::move(state_value)) {}
        std::shared_ptr<QuicStreamState> state;
        memory::ThreadLocalVector<uint8_t> header;
        memory::ThreadLocalDeque<buf::MultiBuffer> output;
        size_t queued_bytes = 0;
        size_t output_offset = 0;
        uint64_t acknowledged = 0;
        memory::ThreadLocalMap<uint64_t, uint64_t> acked_ranges;
        bool fin_pending = false;
        bool raw = false;
        bool dispatched = false;
    };
    struct Core {
        explicit Core(memory::AllocationDomain& domain)
            : memory(domain) {}
        ~Core() {
            if (http) nghttp3_conn_del(http);
            if (quic) ngtcp2_conn_del(quic);
            if (ssl) SSL_free(ssl);
        }
        QuicMemory memory;
        ngtcp2_conn* quic = nullptr;
        nghttp3_conn* http = nullptr;
        SSL* ssl = nullptr;
        ngtcp2_crypto_conn_ref conn_ref{};
        SocketState* socket = nullptr;
        udp::endpoint remote;
        ngtcp2_cid server_cid{};
        memory::ThreadLocalUnorderedMap<int64_t, StreamRecord> streams;
        memory::ThreadLocalUnorderedMap<int64_t, H3Request> h3_requests;
        memory::ThreadLocalDeque<std::vector<uint8_t>> datagrams;
        memory::ThreadLocalUnorderedMap<
            uint32_t, std::shared_ptr<HysteriaUdpLink>> udp_sessions;
        memory::ThreadLocalUnorderedSet<uint32_t> started_udp_sessions;
    };

    Connection(uint32_t worker_id, net::io_context& io,
        routing::Dispatcher& dispatcher, StatsShard& stats,
        std::shared_ptr<ConnectionLimiter> limiter, UserOnlineTracker& online_tracker,
        TimeoutsConfig timeouts, const proxyman::inbound::ReceiverSettings& receiver,
        Settings settings, SharedSslContext ssl_context, SocketState& socket,
        udp::endpoint remote, Spawn spawn, Associate associate,
        Dissociate dissociate, QueuePacket queue_packet)
        : worker_id_(worker_id), io_(io), dispatcher_(dispatcher), stats_(stats),
          limiter_(std::move(limiter)), online_tracker_(online_tracker),
          timeouts_(timeouts), receiver_(receiver), settings_(settings),
          ssl_context_(std::move(ssl_context)), spawn_(std::move(spawn)),
          associate_(std::move(associate)), dissociate_(std::move(dissociate)),
          queue_packet_(std::move(queue_packet)) {
        core_ = std::make_unique<Core>(allocation_);
        core_->socket = &socket;
        core_->remote = std::move(remote);
    }

    static ngtcp2_conn* GetConn(ngtcp2_crypto_conn_ref* ref) {
        return static_cast<Connection*>(ref->user_data)->core_->quic;
    }

    bool Initialize(const ngtcp2_pkt_hd& header) {
        core_->server_cid.datalen = kServerConnectionIdLength;
        if (RAND_bytes(core_->server_cid.data, core_->server_cid.datalen) != 1)
            return false;
        core_->server_cid.data[0] = static_cast<uint8_t>(worker_id_);

        ngtcp2_callbacks callbacks{};
        callbacks.recv_client_initial = ngtcp2_crypto_recv_client_initial_cb;
        callbacks.recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb;
        callbacks.handshake_completed = &HandshakeCompleted;
        callbacks.encrypt = ngtcp2_crypto_encrypt_cb;
        callbacks.decrypt = ngtcp2_crypto_decrypt_cb;
        callbacks.hp_mask = ngtcp2_crypto_hp_mask_cb;
        callbacks.recv_stream_data = &ReceiveStreamData;
        callbacks.acked_stream_data_offset = &AckStreamData;
        callbacks.stream_open = &OpenStream;
        callbacks.stream_close = &CloseStream;
        callbacks.rand = &Random;
        callbacks.get_new_connection_id = &NewConnectionId;
        callbacks.remove_connection_id = &RemoveConnectionId;
        callbacks.update_key = &UpdateKey;
        callbacks.stream_reset = &ResetStream;
        callbacks.extend_max_remote_streams_bidi = &ExtendMaxStreams;
        callbacks.extend_max_stream_data = &ExtendMaxStreamData;
        callbacks.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
        callbacks.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
        callbacks.get_path_challenge_data = ngtcp2_crypto_get_path_challenge_data_cb;
        callbacks.stream_stop_sending = &StopSending;
        callbacks.version_negotiation = ngtcp2_crypto_version_negotiation_cb;
        callbacks.recv_tx_key = &ReceiveTxKey;
        callbacks.recv_datagram = &ReceiveDatagram;

        ngtcp2_settings quic_settings;
        ngtcp2_settings_default(&quic_settings);
        quic_settings.initial_ts = Timestamp();
        quic_settings.cc_algo = NGTCP2_CC_ALGO_BBR;
        quic_settings.handshake_timeout =
            static_cast<ngtcp2_duration>(timeouts_.HandshakeTimeout().count()) * NGTCP2_SECONDS;

        ngtcp2_transport_params parameters;
        ngtcp2_transport_params_default(&parameters);
        parameters.initial_max_stream_data_bidi_local = kMaxStreamData;
        parameters.initial_max_stream_data_bidi_remote = kMaxStreamData;
        parameters.initial_max_stream_data_uni = kMaxStreamData;
        parameters.initial_max_data = kMaxConnectionData;
        parameters.initial_max_streams_bidi = kMaxStreams;
        parameters.initial_max_streams_uni = 16;
        parameters.max_idle_timeout =
            static_cast<ngtcp2_duration>(timeouts_.IdleTimeout().count()) * NGTCP2_SECONDS;
        parameters.max_datagram_frame_size = 65535;
        parameters.active_connection_id_limit = 8;
        parameters.original_dcid_present = 1;
        parameters.original_dcid = header.dcid;

        auto local = MakeAddress(core_->socket->local);
        auto remote = MakeAddress(core_->remote);
        ngtcp2_path path{local, remote, core_->socket};
        if (ngtcp2_conn_server_new(
                &core_->quic, &header.scid, &core_->server_cid, &path,
                header.version, &callbacks, &quic_settings, &parameters,
                core_->memory.Ngtcp2(), this) != 0)
            return false;

        core_->conn_ref = {&GetConn, this};
        core_->ssl = SSL_new(ssl_context_.get());
        if (!core_->ssl) return false;
        SSL_set_app_data(core_->ssl, &core_->conn_ref);
        SSL_set_accept_state(core_->ssl);
        ngtcp2_conn_set_tls_native_handle(core_->quic, core_->ssl);
        return true;
    }

    void Flush();
    void SpawnOwned(net::awaitable<void> task) {
        auto self = shared_from_this();
        spawn_([](std::shared_ptr<Connection> owner,
                  net::awaitable<void> owned_task) -> net::awaitable<void> {
            co_await std::move(owned_task);
            (void)owner;
        }(std::move(self), std::move(task)));
    }
    void Close() noexcept;
    void OnStreamData(uint32_t flags, int64_t stream_id,
                      std::span<const uint8_t> data);
    void StartRawStream(int64_t stream_id, StreamRecord& stream);
    net::awaitable<void> RunRawStream(int64_t stream_id);
    enum class AdmitResult { Admitted, AuthFailed, Limited, DeviceLimited };
    net::awaitable<AdmitResult> AdmitConnection(std::string_view credential);
    net::awaitable<void> RunV1Control(int64_t stream_id);
    net::awaitable<void> AuthenticateV2(int64_t stream_id);
    bool SetupHttp3();
    void SubmitHttpStatus(int64_t stream_id, std::string_view status,
                          bool authenticated);
    void OnHttpHeader(int64_t stream_id, int32_t token,
                      nghttp3_rcbuf* name, nghttp3_rcbuf* value);
    void HandleUdpMessage(const UdpMessage& message);
    std::shared_ptr<HysteriaUdpLink> EnsureUdpSession(uint32_t session_id);
    net::awaitable<void> RunUdpSession(
        uint32_t session_id, TargetAddress first_target,
        std::shared_ptr<HysteriaUdpLink> link);
    bool SendUdpMessage(uint32_t session_id, const TargetAddress& target,
                        std::span<const uint8_t> payload);

    static int HandshakeCompleted(ngtcp2_conn*, void* user_data) {
        auto& self = *static_cast<Connection*>(user_data);
        self.stats_.OnConnectionAccepted();
        self.stats_open_ = true;
        return 0;
    }
    static int ReceiveStreamData(ngtcp2_conn*, uint32_t flags, int64_t stream_id,
        uint64_t, const uint8_t* data, size_t length, void* user_data, void*) {
        static_cast<Connection*>(user_data)->OnStreamData(
            flags, stream_id, {data, length});
        return 0;
    }
    static int AckStreamData(ngtcp2_conn*, int64_t stream_id, uint64_t offset,
        uint64_t length, void* user_data, void*) {
        auto& self = *static_cast<Connection*>(user_data);
        if (self.core_->http &&
            self.core_->h3_requests.contains(stream_id))
            return nghttp3_conn_add_ack_offset(
                self.core_->http, stream_id, length);
        auto it = self.core_->streams.find(stream_id);
        if (it == self.core_->streams.end() || length == 0) return 0;
        auto& stream = it->second;
        uint64_t merged_start = offset;
        uint64_t merged_end = offset + length;
        auto range = stream.acked_ranges.lower_bound(offset);
        if (range != stream.acked_ranges.begin()) {
            auto previous = std::prev(range);
            if (previous->second >= offset) range = previous;
        }
        while (range != stream.acked_ranges.end() &&
               range->first <= merged_end) {
            merged_start = std::min(merged_start, range->first);
            merged_end = std::max(merged_end, range->second);
            range = stream.acked_ranges.erase(range);
        }
        stream.acked_ranges.emplace(merged_start, merged_end);
        const uint64_t previous_acknowledged = stream.acknowledged;
        for (;;) {
            auto first = stream.acked_ranges.begin();
            if (first == stream.acked_ranges.end() ||
                first->first > stream.acknowledged) break;
            stream.acknowledged =
                std::max(stream.acknowledged, first->second);
            stream.acked_ranges.erase(first);
        }
        size_t released = static_cast<size_t>(
            stream.acknowledged - previous_acknowledged);
        stream.queued_bytes -= std::min(stream.queued_bytes, released);
        stream.output_offset -= std::min(stream.output_offset, released);
        while (released != 0 && !stream.output.empty()) {
            const size_t dropped =
                stream.output.front().DropPrefixBytes(released);
            released -= dropped;
            if (stream.output.front().empty()) stream.output.pop_front();
            if (dropped == 0) break;
        }
        return 0;
    }
    static int OpenStream(ngtcp2_conn*, int64_t stream_id, void* user_data) {
        auto& self = *static_cast<Connection*>(user_data);
        if (!ngtcp2_is_bidi_stream(stream_id)) return 0;
        auto state = memory::AllocateShared<QuicStreamState>(
            self.io_, stream_id, self.weak_from_this());
        auto [it, inserted] = self.core_->streams.try_emplace(
            stream_id, std::move(state));
        if (!inserted) return NGTCP2_ERR_CALLBACK_FAILURE;
        if (self.settings_.version == Version::V1 && stream_id == 0) {
            self.SpawnOwned(self.RunV1Control(stream_id));
        } else if (self.authenticated_) {
            self.StartRawStream(stream_id, it->second);
        } else if (self.settings_.version == Version::V2) {
            self.core_->h3_requests.try_emplace(stream_id);
        }
        return 0;
    }
    static int CloseStream(ngtcp2_conn* conn, uint32_t, int64_t stream_id,
        uint64_t, void* user_data, void*) {
        auto& self = *static_cast<Connection*>(user_data);
        if (auto it = self.core_->streams.find(stream_id);
            it != self.core_->streams.end()) {
            it->second.state->RemoteReset();
            self.core_->streams.erase(it);
        }
        self.core_->h3_requests.erase(stream_id);
        if (ngtcp2_is_bidi_stream(stream_id) &&
            !ngtcp2_conn_is_local_stream(conn, stream_id))
            ngtcp2_conn_extend_max_streams_bidi(conn, 1);
        return 0;
    }
    static int ResetStream(ngtcp2_conn*, int64_t stream_id, uint64_t,
        uint64_t, void* user_data, void*) {
        return CloseStream(nullptr, 0, stream_id, 0, user_data, nullptr);
    }
    static int StopSending(ngtcp2_conn*, int64_t stream_id, uint64_t,
        void* user_data, void*) {
        return CloseStream(nullptr, 0, stream_id, 0, user_data, nullptr);
    }
    static void Random(uint8_t* data, size_t length, const ngtcp2_rand_ctx*) {
        if (RAND_bytes(data, length) != 1) std::terminate();
    }
    static int NewConnectionId(ngtcp2_conn*, ngtcp2_cid* cid, uint8_t* token,
        size_t length, void* user_data) {
        auto& self = *static_cast<Connection*>(user_data);
        if (RAND_bytes(cid->data, length) != 1) return NGTCP2_ERR_CALLBACK_FAILURE;
        cid->data[0] = static_cast<uint8_t>(self.worker_id_);
        cid->datalen = length;
        if (RAND_bytes(token, NGTCP2_STATELESS_RESET_TOKENLEN) != 1)
            return NGTCP2_ERR_CALLBACK_FAILURE;
        self.associate_(*cid, self.shared_from_this());
        return 0;
    }
    static int RemoveConnectionId(ngtcp2_conn*, const ngtcp2_cid* cid,
        void* user_data) {
        static_cast<Connection*>(user_data)->dissociate_(*cid);
        return 0;
    }
    static int UpdateKey(ngtcp2_conn* conn, uint8_t* rx_secret,
        uint8_t* tx_secret, ngtcp2_crypto_aead_ctx* rx_ctx, uint8_t* rx_iv,
        ngtcp2_crypto_aead_ctx* tx_ctx, uint8_t* tx_iv,
        const uint8_t* current_rx, const uint8_t* current_tx, size_t secret_length,
        void*) {
        (void)conn;
        std::array<uint8_t, 64> rx_key{}, tx_key{};
        return ngtcp2_crypto_update_key(conn, rx_secret, tx_secret, rx_ctx,
            rx_key.data(), rx_iv, tx_ctx, tx_key.data(), tx_iv,
            current_rx, current_tx, secret_length);
    }
    static int ExtendMaxStreams(ngtcp2_conn*, uint64_t maximum, void* user_data) {
        auto& self = *static_cast<Connection*>(user_data);
        if (self.core_->http)
            nghttp3_conn_set_max_client_streams_bidi(self.core_->http, maximum);
        return 0;
    }
    static int ExtendMaxStreamData(ngtcp2_conn*, int64_t stream_id, uint64_t,
        void* user_data, void*) {
        auto& self = *static_cast<Connection*>(user_data);
        return self.core_->http
            ? nghttp3_conn_unblock_stream(self.core_->http, stream_id) : 0;
    }
    static int ReceiveTxKey(ngtcp2_conn*, ngtcp2_encryption_level level,
        void* user_data) {
        auto& self = *static_cast<Connection*>(user_data);
        return level == NGTCP2_ENCRYPTION_LEVEL_1RTT &&
               self.settings_.version == Version::V2 && !self.SetupHttp3()
            ? NGTCP2_ERR_CALLBACK_FAILURE : 0;
    }
    static int ReceiveDatagram(ngtcp2_conn*, uint32_t flags,
        const uint8_t* data, size_t length, void* user_data) {
        auto& self = *static_cast<Connection*>(user_data);
        if ((flags & NGTCP2_DATAGRAM_FLAG_0RTT) || !self.authenticated_)
            return 0;
        auto message = ParseUdpMessage(self.settings_.version, {data, length});
        if (message) self.HandleUdpMessage(*message);
        return 0;
    }

    uint32_t worker_id_;
    net::io_context& io_;
    routing::Dispatcher& dispatcher_;
    StatsShard& stats_;
    std::shared_ptr<ConnectionLimiter> limiter_;
    UserOnlineTracker& online_tracker_;
    TimeoutsConfig timeouts_;
    const proxyman::inbound::ReceiverSettings& receiver_;
    Settings settings_;
    SharedSslContext ssl_context_;
    Spawn spawn_;
    Associate associate_;
    Dissociate dissociate_;
    QueuePacket queue_packet_;
    memory::AllocationDomain allocation_;
    std::unique_ptr<Core> core_;
    std::optional<ConnectionLimiter::Admission> admission_;
    std::optional<UserOnlineSessionGuard> online_session_;
    std::shared_ptr<const ::acpp::proxyman::inbound::UserStore::HysteriaCredential> user_;
    session::Context base_context_;
    struct PendingFragments {
        TargetAddress target;
        memory::ThreadLocalVector<std::vector<uint8_t>> payloads;
        uint8_t count = 0;
        uint8_t received = 0;
        size_t bytes = 0;
    };
    memory::ThreadLocalUnorderedMap<uint64_t, PendingFragments> fragments_;
    uint32_t next_udp_session_id_ = 1;
    uint16_t next_udp_packet_id_ = 0;
    bool authenticated_ = false;
    bool stats_open_ = false;
    bool in_ngtcp2_callback_ = false;
    bool closed_ = false;
};

buf::MultiBuffer CopyPacket(std::span<const uint8_t> bytes) {
    buf::MultiBuffer output;
    while (!bytes.empty()) {
        buf::BufferGuard buffer(buf::Buffer::New());
        if (!buffer) throw std::bad_alloc();
        const size_t size = std::min(bytes.size(), buffer->Tail().size());
        std::memcpy(buffer->Tail().data(), bytes.data(), size);
        buffer->Produce(static_cast<uint32_t>(size));
        output.push_back(std::move(buffer));
        bytes = bytes.subspan(size);
    }
    return output;
}

void Connection::Flush() {
    if (!core_ || closed_ || !core_->socket || in_ngtcp2_callback_) return;
    std::array<uint8_t, 64 * 1024> packet{};
    for (size_t attempt = 0; attempt < 64; ++attempt) {
        int64_t stream_id = -1;
        int fin = 0;
        std::array<ngtcp2_vec, 16> vectors{};
        size_t vector_count = 0;
        bool http_data = false;
        std::array<nghttp3_vec, 16> http_vectors{};
        if (core_->http) {
            const auto count = nghttp3_conn_writev_stream(
                core_->http, &stream_id, &fin,
                http_vectors.data(), http_vectors.size());
            if (count < 0) {
                Close();
                return;
            }
            vector_count = static_cast<size_t>(count);
            for (size_t i = 0; i < vector_count; ++i)
                vectors[i] = {http_vectors[i].base, http_vectors[i].len};
            http_data = vector_count != 0 || stream_id >= 0;
        }
        if (!http_data) {
            for (auto& [id, stream] : core_->streams) {
                const bool has_unsent =
                    stream.output_offset < stream.queued_bytes;
                if (!has_unsent && !stream.fin_pending) continue;
                stream_id = id;
                fin = stream.fin_pending && !has_unsent;
                size_t skip = stream.output_offset;
                for (size_t output_index = 0;
                     output_index < stream.output.size(); ++output_index) {
                    const auto& multi = stream.output[output_index];
                    for (const auto* buffer : multi) {
                        auto bytes = buffer->Bytes();
                        if (skip >= bytes.size()) {
                            skip -= bytes.size();
                            continue;
                        }
                        bytes = bytes.subspan(skip);
                        skip = 0;
                        vectors[vector_count++] = ngtcp2_vec{
                            const_cast<uint8_t*>(bytes.data()), bytes.size()};
                        if (vector_count == vectors.size()) break;
                    }
                    if (vector_count == vectors.size()) break;
                }
                break;
            }
        }
        auto local = MakeAddress(core_->socket->local);
        auto remote = MakeAddress(core_->remote);
        ngtcp2_path path{local, remote, core_->socket};
        ngtcp2_pkt_info packet_info{};
        if (!core_->datagrams.empty()) {
            auto& datagram = core_->datagrams.front();
            ngtcp2_vec vector{datagram.data(), datagram.size()};
            int accepted_datagram = 0;
            const auto written = ngtcp2_conn_writev_datagram(
                core_->quic, &path, &packet_info, packet.data(), packet.size(),
                &accepted_datagram, NGTCP2_WRITE_DATAGRAM_FLAG_NONE, 0,
                &vector, 1, Timestamp());
            if (written < 0) {
                if (written == NGTCP2_ERR_INVALID_STATE) return;
                Close();
                return;
            }
            if (accepted_datagram) core_->datagrams.pop_front();
            if (written == 0) return;
            auto* output_socket = static_cast<SocketState*>(path.user_data);
            auto output_remote = EndpointFromAddress(path.remote);
            if (!output_socket || !output_remote ||
                !queue_packet_(*output_socket,
                    std::vector<uint8_t>(
                        packet.begin(), packet.begin() + written),
                    *output_remote)) {
                Close();
                return;
            }
            continue;
        }
        ngtcp2_ssize accepted = -1;
        uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_PADDING;
        if (fin) flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;
        const auto written = ngtcp2_conn_writev_stream(
            core_->quic, &path, &packet_info, packet.data(), packet.size(),
            &accepted, flags, stream_id, vectors.data(), vector_count, Timestamp());
        if (written == 0) return;
        if (written < 0) {
            if (written == NGTCP2_ERR_STREAM_DATA_BLOCKED ||
                written == NGTCP2_ERR_STREAM_SHUT_WR) return;
            Close();
            return;
        }
        if (accepted > 0) {
            if (http_data) {
                if (nghttp3_conn_add_write_offset(
                        core_->http, stream_id,
                        static_cast<uint64_t>(accepted)) != 0) {
                    Close();
                    return;
                }
            } else if (auto it = core_->streams.find(stream_id);
                       it != core_->streams.end()) {
                it->second.output_offset += static_cast<size_t>(accepted);
            }
        }
        if (!http_data && fin) {
            if (auto it = core_->streams.find(stream_id);
                it != core_->streams.end()) {
                it->second.fin_pending = false;
            }
        }
        auto* output_socket = static_cast<SocketState*>(path.user_data);
        auto output_remote = EndpointFromAddress(path.remote);
        if (!output_socket || !output_remote ||
            !queue_packet_(*output_socket,
                std::vector<uint8_t>(packet.begin(), packet.begin() + written),
                *output_remote)) {
            Close();
            return;
        }
    }
}

void Connection::Close() noexcept {
    if (closed_) return;
    closed_ = true;
    if (core_) {
        for (auto& [id, stream] : core_->streams) {
            (void)id;
            stream.state->RemoteReset();
        }
        for (auto& [session_id, link] : core_->udp_sessions) {
            (void)session_id;
            link->Close();
        }
        if (core_->quic) dissociate_(core_->server_cid);
    }
    if (stats_open_) {
        stats_.OnConnectionClosed();
        stats_open_ = false;
    }
    online_session_.reset();
    admission_.reset();
}

void Connection::OnStreamData(
    uint32_t flags, int64_t stream_id, std::span<const uint8_t> data) {
    const bool fin = (flags & NGTCP2_STREAM_DATA_FLAG_FIN) != 0;
    auto it = core_->streams.find(stream_id);
    if (settings_.version == Version::V2 &&
        (it == core_->streams.end() || !it->second.raw)) {
        const auto consumed = nghttp3_conn_read_stream2(
            core_->http, stream_id, data.data(), data.size(), fin, Timestamp());
        if (consumed < 0) {
            Close();
            return;
        }
        ngtcp2_conn_extend_max_stream_offset(core_->quic, stream_id, data.size());
        ngtcp2_conn_extend_max_offset(core_->quic, data.size());
        return;
    }
    if (it == core_->streams.end()) return;
    if (settings_.version == Version::V1 && stream_id == 0 &&
        !authenticated_) {
        if (!it->second.state->PushInput(data, fin)) CancelStream(stream_id);
        return;
    }
    auto& stream = it->second;
    if (!stream.dispatched) {
        if (stream.header.size() > kMaxStreamHeaderBytes - data.size()) {
            CancelStream(stream_id);
            return;
        }
        stream.header.insert(stream.header.end(), data.begin(), data.end());
        StartRawStream(stream_id, stream);
        if (fin && !stream.dispatched) stream.state->RemoteReset();
        return;
    }
    if (!stream.state->PushInput(data, fin)) CancelStream(stream_id);
}

void Connection::StartRawStream(int64_t stream_id, StreamRecord& stream) {
    stream.raw = true;
    if (stream.dispatched) return;
    size_t consumed = 0;
    if (settings_.version == Version::V1) {
        auto request = ParseV1Request(stream.header);
        if (!request) {
            if (request.error() != ProtocolError::Incomplete) CancelStream(stream_id);
            return;
        }
        if (request->udp) {
            const uint32_t session_id = next_udp_session_id_++;
            if (session_id == 0 || !EnsureUdpSession(session_id)) {
                CancelStream(stream_id);
                return;
            }
            auto response = EncodeV1Response(true, session_id, "");
            stream.output.push_back(CopyPacket(response));
            stream.queued_bytes += response.size();
            stream.dispatched = true;
            Flush();
            return;
        }
        consumed = request->header_bytes;
    } else {
        auto request = ParseV2TcpRequest(stream.header);
        if (!request) {
            if (request.error() != ProtocolError::Incomplete) CancelStream(stream_id);
            return;
        }
        consumed = request->header_bytes;
    }
    stream.dispatched = true;
    if (stream.header.size() > consumed) {
        if (!stream.state->PushInput(
                {stream.header.data() + consumed,
                 stream.header.size() - consumed}, false)) {
            CancelStream(stream_id);
            return;
        }
    }
    SpawnOwned(RunRawStream(stream_id));
}

net::awaitable<void> Connection::RunRawStream(int64_t stream_id) {
    auto it = core_->streams.find(stream_id);
    if (it == core_->streams.end() || !authenticated_) co_return;
    auto state = it->second.state;
    TargetAddress target;
    std::vector<uint8_t> response;
    if (settings_.version == Version::V1) {
        auto parsed = ParseV1Request(it->second.header);
        if (!parsed || parsed->udp) co_return;
        target = std::move(parsed->target);
        response = EncodeV1Response(true, 0, "");
    } else {
        auto parsed = ParseV2TcpRequest(it->second.header);
        if (!parsed) co_return;
        target = std::move(parsed->target);
        response = EncodeV2TcpResponse(true, "");
    }
    it->second.header.clear();
    co_await state->WriteMultiBuffer(CopyPacket(response));
    session::Context context;
    context.InitSubstreamFrom(base_context_,
        static_cast<uint16_t>(stream_id & 0xffff));
    context.outbound.original_target = target;
    context.outbound.target = target;
    context.outbound.route_target = target;
    context.content.network = Network::TCP;
    auto stream = std::make_unique<QuicStream>(std::move(state));
    auto* link_stream = stream.get();
    (void)co_await dispatcher_.Dispatch(
        io_, receiver_.dispatch_policy, std::move(stream),
        transport::Link{link_stream, link_stream}, InitialPayload{},
        context, stats_, timeouts_);
    core_->streams.erase(stream_id);
}

std::shared_ptr<HysteriaUdpLink>
Connection::EnsureUdpSession(uint32_t session_id) {
    if (auto it = core_->udp_sessions.find(session_id);
        it != core_->udp_sessions.end()) return it->second;
    if (core_->udp_sessions.size() >= 256) return {};
    auto weak = weak_from_this();
    auto link = memory::AllocateShared<HysteriaUdpLink>(
        io_, [weak, session_id](const TargetAddress& target,
                               std::span<const uint8_t> payload) {
            auto owner = weak.lock();
            return owner && owner->SendUdpMessage(
                session_id, target, payload);
        });
    core_->udp_sessions.emplace(session_id, link);
    return link;
}

void Connection::HandleUdpMessage(const UdpMessage& message) {
    if (message.fragment_count == 1) {
        auto link = EnsureUdpSession(message.session_id);
        if (link && message.target.IsValid() &&
            link->Push(message.target, message.payload) &&
            core_->started_udp_sessions.insert(message.session_id).second) {
            SpawnOwned(RunUdpSession(
                message.session_id, message.target, link));
        }
        return;
    }
    const uint64_t key =
        (static_cast<uint64_t>(message.session_id) << 16) | message.packet_id;
    auto it = fragments_.find(key);
    if (it == fragments_.end()) {
        if (fragments_.size() >= 64 || message.fragment_id != 0 ||
            !message.target.IsValid()) return;
        PendingFragments pending;
        pending.target = message.target;
        pending.count = message.fragment_count;
        pending.payloads.resize(message.fragment_count);
        it = fragments_.emplace(key, std::move(pending)).first;
    }
    auto& pending = it->second;
    if (pending.count != message.fragment_count ||
        message.fragment_id >= pending.payloads.size() ||
        !pending.payloads[message.fragment_id].empty() ||
        pending.bytes > kMaxUdpPayloadLength - message.payload.size()) {
        fragments_.erase(it);
        return;
    }
    auto& part = pending.payloads[message.fragment_id];
    part.assign(message.payload.begin(), message.payload.end());
    pending.bytes += part.size();
    ++pending.received;
    if (pending.received != pending.count) return;
    std::vector<uint8_t> payload;
    payload.reserve(pending.bytes);
    for (const auto& fragment : pending.payloads)
        payload.insert(payload.end(), fragment.begin(), fragment.end());
    auto link = EnsureUdpSession(message.session_id);
    const TargetAddress target = pending.target;
    if (link && link->Push(target, payload) &&
        core_->started_udp_sessions.insert(message.session_id).second) {
        SpawnOwned(RunUdpSession(message.session_id, target, link));
    }
    fragments_.erase(it);
}

bool Connection::SendUdpMessage(
    uint32_t session_id, const TargetAddress& target,
    std::span<const uint8_t> payload) {
    constexpr size_t kFragmentPayload = 1100;
    if (!target.IsValid() || payload.empty() ||
        payload.size() > kMaxUdpPayloadLength ||
        core_->datagrams.size() >= 1024) return false;
    const size_t fragments =
        (payload.size() + kFragmentPayload - 1) / kFragmentPayload;
    const uint16_t packet_id = next_udp_packet_id_++;
    for (size_t index = 0; index < fragments; ++index) {
        const size_t offset = index * kFragmentPayload;
        UdpMessage message;
        message.session_id = session_id;
        message.packet_id = packet_id;
        message.fragment_id = static_cast<uint8_t>(index);
        message.fragment_count = static_cast<uint8_t>(fragments);
        if (settings_.version == Version::V1 || index == 0)
            message.target = target;
        message.payload = payload.subspan(
            offset, std::min(kFragmentPayload, payload.size() - offset));
        auto encoded = EncodeUdpMessage(settings_.version, message);
        if (!encoded) return false;
        core_->datagrams.push_back(std::move(*encoded));
    }
    Flush();
    return true;
}

net::awaitable<void> Connection::RunUdpSession(
    uint32_t session_id, TargetAddress first_target,
    std::shared_ptr<HysteriaUdpLink> link) {
    session::Context context;
    context.InitSubstreamFrom(
        base_context_, static_cast<uint16_t>(session_id & 0xffff));
    context.outbound.original_target = first_target;
    context.outbound.target = first_target;
    context.outbound.route_target = first_target;
    context.content.network = Network::UDP;
    (void)co_await dispatcher_.Dispatch(
        io_, receiver_.dispatch_policy, nullptr,
        transport::Link{link.get(), link.get()}, InitialPayload{},
        context, stats_, timeouts_);
    link->Close();
    core_->started_udp_sessions.erase(session_id);
    core_->udp_sessions.erase(session_id);
}

net::awaitable<Connection::AdmitResult> Connection::AdmitConnection(
    std::string_view credential) {
    base_context_.conn_id = session::NewID(worker_id_);
    base_context_.worker_id = worker_id_;
    base_context_.inbound.source_addr = core_->remote.address();
    base_context_.inbound.source_ip = core_->remote.address().to_string();
    base_context_.inbound.source_port = core_->remote.port();
    base_context_.inbound.tag = receiver_.inbound_tag;
    base_context_.inbound.accounting_key = receiver_.accounting_key;
    base_context_.content.protocol = receiver_.protocol;
    user_ = proxyman::inbound::UserStore::FindHysteriaUser(
        receiver_.inbound_tag, HashCredential(credential));
    if (!user_) {
        co_await RecordInboundAuthFailure(
            limiter_.get(), base_context_, "no matching credential");
        stats_.OnError();
        co_return AdmitResult::AuthFailed;
    }
    if (limiter_) {
        auto admission = co_await limiter_->ReservePhysical(
            receiver_.inbound_tag, base_context_.inbound.source_ip, true);
        if (admission.reason != ConnectionLimiter::RejectReason::NONE) {
            co_return AdmitResult::Limited;
        }
        admission_.emplace(std::move(admission));
    }
    const auto profile = user_->profile;
    user_.reset();
    BindAuthenticatedInbound(base_context_, profile, std::nullopt);
    auto session = co_await AdmitAuthenticatedInbound(
        online_tracker_, base_context_, profile);
    if (!session) co_return AdmitResult::DeviceLimited;
    online_session_.emplace(std::move(*session));
    authenticated_ = true;
    co_return AdmitResult::Admitted;
}

net::awaitable<void> Connection::RunV1Control(int64_t stream_id) {
    auto it = core_->streams.find(stream_id);
    if (it == core_->streams.end()) co_return;
    auto state = it->second.state;
    memory::ThreadLocalVector<uint8_t> hello_bytes;
    std::array<uint8_t, 4096> buffer{};
    tl::expected<V1ClientHello, ProtocolError> hello =
        tl::unexpected(ProtocolError::Incomplete);
    while (!hello) {
        const size_t bytes = co_await state->Read(net::buffer(buffer));
        if (bytes == 0 || hello_bytes.size() > kMaxAuthLength + 32 - bytes) co_return;
        hello_bytes.insert(hello_bytes.end(), buffer.begin(), buffer.begin() + bytes);
        hello = ParseV1ClientHello(hello_bytes);
        if (!hello && hello.error() != ProtocolError::Incomplete) co_return;
    }
    const auto result = co_await AdmitConnection(hello->auth);
    if (result == AdmitResult::AuthFailed) {
        auto response = EncodeV1ServerHello(false, 0, 0, "authentication failed");
        co_await state->WriteMultiBuffer(CopyPacket(response));
        co_return;
    }
    if (result != AdmitResult::Admitted) co_return;
    auto response = EncodeV1ServerHello(
        true, settings_.download_bytes_per_second,
        settings_.upload_bytes_per_second, "");
    co_await state->WriteMultiBuffer(CopyPacket(response));
    for (auto& [id, candidate] : core_->streams) {
        if (id != stream_id && !candidate.raw) StartRawStream(id, candidate);
    }
}

bool Connection::SetupHttp3() {
    if (core_->http) return true;
    nghttp3_callbacks callbacks{};
    callbacks.begin_headers = [](nghttp3_conn*, int64_t stream_id,
        void* user_data, void*) {
        auto& self = *static_cast<Connection*>(user_data);
        self.core_->h3_requests.insert_or_assign(stream_id, H3Request{});
        return 0;
    };
    callbacks.recv_header = [](nghttp3_conn*, int64_t stream_id, int32_t token,
        nghttp3_rcbuf* name, nghttp3_rcbuf* value, uint8_t,
        void* user_data, void*) {
        static_cast<Connection*>(user_data)->OnHttpHeader(
            stream_id, token, name, value);
        return 0;
    };
    callbacks.end_headers = [](nghttp3_conn*, int64_t stream_id, int,
        void* user_data, void*) {
        auto& self = *static_cast<Connection*>(user_data);
        self.SpawnOwned(self.AuthenticateV2(stream_id));
        return 0;
    };
    callbacks.stop_sending = [](nghttp3_conn*, int64_t stream_id,
        uint64_t code, void* user_data, void*) {
        return ngtcp2_conn_shutdown_stream_read(
            static_cast<Connection*>(user_data)->core_->quic,
            0, stream_id, code);
    };
    callbacks.reset_stream = [](nghttp3_conn*, int64_t stream_id,
        uint64_t code, void* user_data, void*) {
        return ngtcp2_conn_shutdown_stream_write(
            static_cast<Connection*>(user_data)->core_->quic,
            0, stream_id, code);
    };
    callbacks.rand = [](uint8_t* data, size_t length) {
        if (RAND_bytes(data, length) != 1) std::terminate();
    };
    nghttp3_settings http_settings;
    nghttp3_settings_default(&http_settings);
    http_settings.qpack_max_dtable_capacity = 4096;
    http_settings.qpack_blocked_streams = 32;
    if (nghttp3_conn_server_new(&core_->http, &callbacks, &http_settings,
            core_->memory.Nghttp3(), this) != 0) return false;
    nghttp3_conn_set_max_client_streams_bidi(core_->http, kMaxStreams);
    int64_t control = -1, encoder = -1, decoder = -1;
    return ngtcp2_conn_open_uni_stream(core_->quic, &control, nullptr) == 0 &&
           nghttp3_conn_bind_control_stream(core_->http, control) == 0 &&
           ngtcp2_conn_open_uni_stream(core_->quic, &encoder, nullptr) == 0 &&
           ngtcp2_conn_open_uni_stream(core_->quic, &decoder, nullptr) == 0 &&
           nghttp3_conn_bind_qpack_streams(core_->http, encoder, decoder) == 0;
}

void Connection::OnHttpHeader(int64_t stream_id, int32_t token,
    nghttp3_rcbuf* name, nghttp3_rcbuf* value) {
    auto it = core_->h3_requests.find(stream_id);
    if (it == core_->h3_requests.end()) return;
    const auto name_buffer = nghttp3_rcbuf_get_buf(name);
    const auto value_buffer = nghttp3_rcbuf_get_buf(value);
    const std::string_view header_name{
        reinterpret_cast<const char*>(name_buffer.base), name_buffer.len};
    const std::string header_value{
        reinterpret_cast<const char*>(value_buffer.base), value_buffer.len};
    if (token == NGHTTP3_QPACK_TOKEN__METHOD) it->second.method = header_value;
    else if (token == NGHTTP3_QPACK_TOKEN__PATH) it->second.path = header_value;
    else if (token == NGHTTP3_QPACK_TOKEN__AUTHORITY)
        it->second.authority = header_value;
    else if (header_name == "hysteria-auth") it->second.auth = header_value;
}

void Connection::SubmitHttpStatus(
    int64_t stream_id, std::string_view status, bool accepted) {
    static constexpr std::string_view kStatus = ":status";
    static constexpr std::string_view kUdp = "hysteria-udp";
    static constexpr std::string_view kTrue = "true";
    std::array<nghttp3_nv, 2> headers{{
        {reinterpret_cast<uint8_t*>(const_cast<char*>(kStatus.data())),
         reinterpret_cast<uint8_t*>(const_cast<char*>(status.data())),
         kStatus.size(), status.size(), NGHTTP3_NV_FLAG_NONE},
        {reinterpret_cast<uint8_t*>(const_cast<char*>(kUdp.data())),
         reinterpret_cast<uint8_t*>(const_cast<char*>(kTrue.data())),
         kUdp.size(), kTrue.size(), NGHTTP3_NV_FLAG_NONE},
    }};
    const size_t count = accepted ? headers.size() : 1;
    if (nghttp3_conn_submit_response(
            core_->http, stream_id, headers.data(), count, nullptr) != 0) {
        Close();
        return;
    }
    Flush();
}

net::awaitable<void> Connection::AuthenticateV2(int64_t stream_id) {
    auto it = core_->h3_requests.find(stream_id);
    if (it == core_->h3_requests.end()) co_return;
    const auto request = std::move(it->second);
    if (authenticated_ || request.method != "POST" ||
        request.path != "/auth" || request.authority != "hysteria" ||
        request.auth.empty()) {
        SubmitHttpStatus(stream_id, "404", false);
        co_return;
    }
    const auto result = co_await AdmitConnection(request.auth);
    if (result == AdmitResult::AuthFailed) {
        SubmitHttpStatus(stream_id, "404", false);
        co_return;
    }
    if (result != AdmitResult::Admitted) {
        SubmitHttpStatus(stream_id, "429", false);
        co_return;
    }
    SubmitHttpStatus(stream_id, "233", true);
}

}  // namespace

struct HysteriaIngress::Impl final : memory::ThreadAllocated {
    using ConnectionMap = memory::ThreadLocalUnorderedMap<
        ConnectionId, std::shared_ptr<Connection>, ConnectionIdHash>;

    Impl(uint32_t worker_id_value, net::io_context& io_value,
         routing::Dispatcher& dispatcher_value, StatsShard& stats_value,
         std::shared_ptr<ConnectionLimiter> limiter_value,
         UserOnlineTracker& tracker_value, TimeoutsConfig timeouts_value,
         std::shared_ptr<const proxyman::inbound::BuildRequest> request_value,
         std::shared_ptr<const proxyman::inbound::ReceiverSettings> receiver_value)
        : worker_id(worker_id_value), io(io_value), dispatcher(dispatcher_value),
          stats(stats_value), limiter(std::move(limiter_value)), tracker(tracker_value),
          timeouts(timeouts_value), request(std::move(request_value)),
          receiver(std::move(receiver_value)), changed(io), expiry(io) {
        settings = GetSettings(*request);
        if (!settings) throw std::invalid_argument("missing Hysteria settings");
        ssl_context = BuildSslContext(receiver->stream_settings, settings->version);
        if (!ssl_context) throw std::invalid_argument("invalid Hysteria TLS settings");
    }

    void Spawn(net::awaitable<void> task) {
        ++tasks;
        net::co_spawn(io, std::move(task), [this](std::exception_ptr error) {
            --tasks;
            changed.cancel();
            if (!error || stopping) return;
            try { std::rethrow_exception(error); }
            catch (const std::exception& failure) {
                LOG_ERROR("Hysteria task failed worker={} > {}", worker_id, failure.what());
            } catch (...) {
                LOG_ERROR("Hysteria task failed worker={} > unknown error", worker_id);
            }
        });
    }

    bool Queue(SocketState& socket, std::vector<uint8_t> data,
               udp::endpoint remote) {
        if (stopping || socket.output.size() >= kMaxQueuedSocketPackets) return false;
        socket.output.push_back({std::move(data), std::move(remote)});
        (void)socket.changed.try_send(IoErrorCode{});
        return true;
    }

    void Associate(const ngtcp2_cid& cid, std::shared_ptr<Connection> connection) {
        connections.insert_or_assign(ConnectionId(cid), std::move(connection));
    }
    void Dissociate(const ngtcp2_cid& cid) { connections.erase(ConnectionId(cid)); }

    net::awaitable<void> ReceiveLoop(std::shared_ptr<SocketState> socket) {
        while (!stopping && socket->socket && socket->socket->is_open()) {
            auto [error, bytes] = co_await socket->socket->async_receive_from(
                net::buffer(socket->receive_buffer), socket->remote,
                net::as_tuple(net::use_awaitable));
            if (error == net::error::operation_aborted) co_return;
            if (error || bytes == 0) continue;
            ngtcp2_version_cid version_cid{};
            if (ngtcp2_pkt_decode_version_cid(
                    &version_cid, socket->receive_buffer.data(), bytes,
                    kServerConnectionIdLength) != 0)
                continue;
            auto found = connections.find(
                ConnectionId(version_cid.dcid, version_cid.dcidlen));
            std::shared_ptr<Connection> connection =
                found == connections.end() ? nullptr : found->second;
            if (!connection) {
                if (connections.size() >= 65536) {
                    stats.OnError();
                    continue;
                }
                ngtcp2_pkt_hd header{};
                if (ngtcp2_accept(&header, socket->receive_buffer.data(), bytes) != 0)
                    continue;
                connection = Connection::Create(worker_id, io, dispatcher, stats,
                    limiter, tracker, timeouts, *receiver, *settings, ssl_context,
                    *socket, socket->remote, header,
                    [this](net::awaitable<void> task) { Spawn(std::move(task)); },
                    [this](const ngtcp2_cid& cid, std::shared_ptr<Connection> value) {
                        Associate(cid, std::move(value));
                    },
                    [this](const ngtcp2_cid& cid) { Dissociate(cid); },
                    [this](SocketState& owner, std::vector<uint8_t> data,
                           udp::endpoint remote) {
                        return Queue(owner, std::move(data), std::move(remote));
                    });
                if (!connection) continue;
                Associate(header.dcid, connection);
            }
            if (!connection->Feed(*socket, socket->remote,
                    {socket->receive_buffer.data(), bytes})) {
                std::erase_if(connections, [&](const auto& entry) {
                    return entry.second == connection;
                });
            }
            ArmExpiry();
        }
    }

    net::awaitable<void> SendLoop(std::shared_ptr<SocketState> socket) {
        while (!stopping && socket->socket && socket->socket->is_open()) {
            if (socket->output.empty()) {
                auto [error] = co_await socket->changed.async_receive(
                    net::as_tuple(net::use_awaitable));
                if (error && stopping) co_return;
                continue;
            }
            auto packet = std::move(socket->output.front());
            socket->output.pop_front();
            auto [error, bytes] = co_await socket->socket->async_send_to(
                net::buffer(packet.data), packet.remote,
                net::as_tuple(net::use_awaitable));
            (void)bytes;
            if (error == net::error::operation_aborted) co_return;
        }
    }

    void ArmExpiry() {
        ngtcp2_tstamp nearest = std::numeric_limits<ngtcp2_tstamp>::max();
        for (const auto& [id, connection] : connections) {
            (void)id;
            if (connection && !connection->Closed())
                nearest = std::min(nearest, connection->Expiry());
        }
        if (nearest == std::numeric_limits<ngtcp2_tstamp>::max()) return;
        expiry.expires_at(std::chrono::steady_clock::time_point(
            std::chrono::nanoseconds(nearest)));
        if (!expiry_running) {
            expiry_running = true;
            Spawn(ExpiryLoop());
        }
    }

    net::awaitable<void> ExpiryLoop() {
        while (!stopping) {
            auto [error] = co_await expiry.async_wait(
                net::as_tuple(net::use_awaitable));
            if (error == net::error::operation_aborted) {
                if (stopping) break;
                continue;
            }
            const auto now = Timestamp();
            memory::ThreadLocalVector<std::shared_ptr<Connection>> unique;
            for (const auto& [id, connection] : connections) {
                (void)id;
                if (connection && connection->Expiry() <= now &&
                    std::find(unique.begin(), unique.end(), connection) ==
                        unique.end())
                    unique.push_back(connection);
            }
            for (auto& connection : unique) connection->OnExpiry();
            std::erase_if(connections, [](const auto& entry) {
                return !entry.second || entry.second->Closed();
            });

            ngtcp2_tstamp nearest =
                std::numeric_limits<ngtcp2_tstamp>::max();
            for (const auto& [id, connection] : connections) {
                (void)id;
                if (connection && !connection->Closed())
                    nearest = std::min(nearest, connection->Expiry());
            }
            if (nearest == std::numeric_limits<ngtcp2_tstamp>::max()) break;
            expiry.expires_at(std::chrono::steady_clock::time_point(
                std::chrono::nanoseconds(nearest)));
        }
        expiry_running = false;
    }

    uint32_t worker_id;
    net::io_context& io;
    routing::Dispatcher& dispatcher;
    StatsShard& stats;
    std::shared_ptr<ConnectionLimiter> limiter;
    UserOnlineTracker& tracker;
    TimeoutsConfig timeouts;
    std::shared_ptr<const proxyman::inbound::BuildRequest> request;
    std::shared_ptr<const proxyman::inbound::ReceiverSettings> receiver;
    const Settings* settings = nullptr;
    SharedSslContext ssl_context;
    memory::ThreadLocalUnorderedMap<memory::ThreadLocalString,
        std::shared_ptr<SocketState>, TransparentStringHash, TransparentStringEq> sockets;
    ConnectionMap connections;
    net::steady_timer changed;
    net::steady_timer expiry;
    size_t tasks = 0;
    bool stopping = false;
    bool started = false;
    bool expiry_running = false;
};

HysteriaIngress::HysteriaIngress(
    uint32_t worker_id, net::io_context& io_context,
    routing::Dispatcher& dispatcher, StatsShard& stats,
    std::shared_ptr<ConnectionLimiter> limiter, UserOnlineTracker& online_tracker,
    TimeoutsConfig timeouts,
    std::shared_ptr<const proxyman::inbound::BuildRequest> request,
    std::shared_ptr<const proxyman::inbound::ReceiverSettings> receiver)
    : impl_(std::make_unique<Impl>(worker_id, io_context, dispatcher, stats,
          std::move(limiter), online_tracker, timeouts,
          std::move(request), std::move(receiver))) {}

HysteriaIngress::~HysteriaIngress() noexcept { RequestStop(); }

HysteriaIngress::SocketPtr HysteriaIngress::MakeSocket() {
    return memory::AllocateShared<udp::socket>(impl_->io);
}

HysteriaIngress::SocketPtr HysteriaIngress::AttachSocket(
    std::string_view socket_key, SocketPtr socket) {
    if (!socket || !socket->is_open() || impl_->started || impl_->stopping)
        return {};
    auto state = memory::AllocateShared<SocketState>(impl_->io);
    state->socket = std::move(socket);
    state->key.assign(socket_key);
    IoErrorCode error;
    state->local = state->socket->local_endpoint(error);
    if (error) return {};
    auto [it, inserted] = impl_->sockets.try_emplace(state->key, state);
    return inserted ? it->second->socket : SocketPtr{};
}

bool HysteriaIngress::OwnsSocket(
    std::string_view socket_key, const udp::socket* socket) const noexcept {
    auto it = impl_->sockets.find(socket_key);
    return it != impl_->sockets.end() && it->second->socket.get() == socket;
}

void HysteriaIngress::Start() {
    if (impl_->started || impl_->stopping) return;
    impl_->started = true;
    for (auto& [key, socket] : impl_->sockets) {
        (void)key;
        impl_->Spawn(impl_->ReceiveLoop(socket));
        impl_->Spawn(impl_->SendLoop(socket));
    }
}

void HysteriaIngress::RequestStop() noexcept {
    if (!impl_ || impl_->stopping) return;
    impl_->stopping = true;
    IoErrorCode ignored;
    impl_->expiry.cancel();
    impl_->changed.cancel();
    for (auto& [key, socket] : impl_->sockets) {
        (void)key;
        socket->changed.cancel();
        if (socket->socket) socket->socket->close(ignored);
    }
    impl_->connections.clear();
}

net::awaitable<void> HysteriaIngress::AsyncJoin() {
    RequestStop();
    while (impl_->tasks != 0) {
        impl_->changed.expires_at(std::chrono::steady_clock::time_point::max());
        auto [error] = co_await impl_->changed.async_wait(net::as_tuple(net::use_awaitable));
        (void)error;
    }
}

std::string_view HysteriaIngress::Tag() const noexcept {
    return impl_->receiver->inbound_tag;
}

size_t HysteriaIngress::ConnectionCount() const noexcept {
    return impl_->connections.size();
}

}  // namespace acpp::proxy::hysteria
