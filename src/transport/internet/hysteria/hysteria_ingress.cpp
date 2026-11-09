#include "hysteria_ingress.hpp"

#include "hysteria_protocol.hpp"

#include "app/proxyman/inbound/handler.hpp"
#include "app/proxyman/inbound/receiver_settings.hpp"
#include "app/proxyman/inbound/user_store.hpp"
#include "app/rate_limiter.hpp"
#include "app/session_group_executor.hpp"
#include "app/stats.hpp"
#include "common/buf/multi_buffer.hpp"
#include "common/ip_utils.hpp"
#include "common/container_util.hpp"
#include "common/session.hpp"
#include "common/sharded_user_stats.hpp"
#include "common/string_hash.hpp"
#include "infra/config_types.hpp"
#include "infra/log.hpp"
#include "transport/internet/transport_stack.hpp"
#include "transport/internet/timeout_scheduler.hpp"
#include "../reality_tls.hpp"
#include "../../../proxy/inbound_admission.hpp"
#include "../../../common/awaitable_task_group.hpp"
#include "../../../app/worker/udp_receive_loop.hpp"

#include <nghttp3/nghttp3.h>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_boringssl.h>

#include <openssl/rand.h>
#include <openssl/ssl.h>

#include <asio/as_tuple.hpp>
#include <asio/co_spawn.hpp>
#include <asio/steady_timer.hpp>
#include <asio/this_coro.hpp>
#include <asio/use_awaitable.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <limits>
#include <new>
#include <optional>
#include <stdexcept>
#include <utility>

namespace transport::internet::hysteria {

namespace {


// ngtcp2/nghttp3 do not provide allocation sizes to free(). Prefix each block
// with its exact PMR layout so Free can return slots to the current Worker's
// shared pool without a side table.
class QuicMemory final {
public:
    [[nodiscard]] static const ngtcp2_mem* Ngtcp2() noexcept {
        static const ngtcp2_mem kMem{nullptr, &Allocate, &Free, &Callocate, &Reallocate};
        return &kMem;
    }

    [[nodiscard]] static const nghttp3_mem* Nghttp3() noexcept {
        static const nghttp3_mem kMem{nullptr, &Allocate, &Free, &Callocate, &Reallocate};
        return &kMem;
    }

private:
    struct alignas(std::max_align_t) AllocationHeader {
        size_t payload_size;
        size_t allocation_size;
    };

    static constexpr size_t kAlignment = alignof(std::max_align_t);

    [[nodiscard]] static bool AllocationSize(size_t payload_size, size_t& result) noexcept {
        if (payload_size > std::numeric_limits<size_t>::max() - sizeof(AllocationHeader))
            return false;
        result = sizeof(AllocationHeader) + payload_size;
        return true;
    }

    static void* Allocate(size_t size, void*) {
        try {
            size_t allocation_size = 0;
            if (!AllocationSize(size, allocation_size)) return nullptr;
            void* raw =
                memory::ThreadMemoryPool().Allocate(allocation_size, kAlignment);
            if (!raw) return nullptr;
            auto* header =
                ::new (raw) AllocationHeader{size, allocation_size};
            return header + 1;
        } catch (...) {
            return nullptr;
        }
    }

    static void Free(void* pointer, void*) noexcept {
        if (!pointer) return;
        auto* header = static_cast<AllocationHeader*>(pointer) - 1;
        const size_t allocation_size = header->allocation_size;
        header->~AllocationHeader();
        memory::ThreadMemoryPool().Deallocate(
            header, allocation_size, kAlignment);
    }

    static void* Callocate(size_t count, size_t size, void* user_data) {
        if (size != 0 && count > std::numeric_limits<size_t>::max() / size)
            return nullptr;
        const size_t bytes = count * size;
        void* pointer = Allocate(bytes, user_data);
        if (pointer) std::memset(pointer, 0, bytes);
        return pointer;
    }

    static void* Reallocate(void* pointer, size_t size, void* user_data) {
        if (!pointer) return Allocate(size, user_data);
        if (size == 0) {
            Free(pointer, user_data);
            return nullptr;
        }
        auto* old_header = static_cast<AllocationHeader*>(pointer) - 1;
        void* replacement = Allocate(size, user_data);
        if (!replacement) return nullptr;
        std::memcpy(replacement, pointer, std::min(old_header->payload_size, size));
        Free(pointer, user_data);
        return replacement;
    }
};
constexpr size_t kMaxPacketSize = 64 * 1024;
constexpr size_t kMaxQueuedSocketPackets = 1024;
constexpr size_t kMaxConnections = 65536;
constexpr size_t kMaxStreamHeaderBytes = 8192;
constexpr size_t kMaxUdpSessions = 256;
constexpr size_t kMaxPendingFragments = 64;
// 丢片无法补齐原包，必须限制孤片在长连接中的滞留，而非等待连接关闭。
constexpr ngtcp2_duration kUdpFragmentIdleTimeout = 5 * NGTCP2_SECONDS;
constexpr ngtcp2_duration kUdpFragmentLifetime = 15 * NGTCP2_SECONDS;
constexpr size_t kMaxQueuedDatagrams = 1024;
// 完整 HY 报文预算为 1100B，给最小 1200B QUIC 路径保留封包开销。
constexpr size_t kMaxUdpMessageSize = 1100;
constexpr size_t kUdpDatagramFrameOverhead = 3; // type + 至多两字节 LEN。
constexpr size_t kMaxStreamOutputBytes = 512 * 1024;
constexpr uint64_t kMaxConnectionData = 16 * 1024 * 1024;
constexpr uint64_t kMaxStreamData = QuicStreamState::kMaxQueuedInputBytes;
constexpr uint64_t kMaxStreams = 1024;

[[nodiscard]] ngtcp2_tstamp Timestamp() noexcept {
    return static_cast<ngtcp2_tstamp>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
}

[[nodiscard]] ngtcp2_tstamp UdpFragmentDeadline(
    ngtcp2_tstamp now, ngtcp2_duration delay) noexcept {
    const auto maximum = std::numeric_limits<ngtcp2_tstamp>::max();
    return maximum - now < delay ? maximum : now + delay;
}

[[nodiscard]] std::chrono::steady_clock::time_point ExpiryTimePoint(
    ngtcp2_tstamp timestamp) noexcept {
    constexpr auto kMaxNanoseconds = static_cast<ngtcp2_tstamp>(
        std::chrono::steady_clock::time_point::max().time_since_epoch().count());
    if (timestamp >= kMaxNanoseconds)
        return std::chrono::steady_clock::time_point::max();
    return std::chrono::steady_clock::time_point(
        std::chrono::nanoseconds(static_cast<std::chrono::nanoseconds::rep>(timestamp)));
}

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

[[nodiscard]] SslContextPtr BuildSslContext(
    const StreamSettings& stream_settings, Version version) {
    if (!stream_settings.IsTls() || !stream_settings.tls.pem ||
        !stream_settings.tls.HasCertificatePair()) {
        LOG_ERROR("Hysteria requires a prepared TLS certificate and private key");
        return {};
    }
    SslContextPtr context{SSL_CTX_new(TLS_server_method())};
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
    return context;
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

[[nodiscard]] buf::MultiBuffer CopyPacket(std::span<const uint8_t> bytes) {
    buf::MultiBuffer output;
    if (!buf::AppendSpanToMultiBuffer(bytes, output)) throw std::bad_alloc();
    return output;
}

}  // namespace


struct SocketState final : memory::ThreadAllocated {
    explicit SocketState(net::io_context& io)
        : changed(io, 1) {}
    HysteriaIngress::SocketPtr socket;
    memory::ThreadLocalString key;
    udp::endpoint local;
    udp::endpoint remote;
    struct Output {
        memory::ByteVector data;
        udp::endpoint remote;
        std::shared_ptr<Connection> connection;
        bool terminal = false;
    };
    memory::ThreadLocalDeque<Output> output;
    SignalChannel changed;
};

const proxyman::inbound::ReceiverSettings& HysteriaIngress::Receiver() const noexcept {
    return environment.handler->ReceiverSettings();
}

Connection::Connection(
    HysteriaIngress& listener, SocketState& socket, const udp::endpoint& remote)
    : listener_(&listener)
    , closed_signal_(listener.io.get_executor(), 1)
    , core_(std::in_place)
    , physical_ready_(listener.io.get_executor(), 1) {
    core_->local = socket.local;
    core_->remote = remote;
    InitializeBaseContext(remote);
}

net::io_context& Connection::Reactor() const noexcept {
    return listener_->io;
}

std::shared_ptr<Connection> Connection::Create(
    HysteriaIngress& listener, SocketState& socket,
    const udp::endpoint& remote, const ngtcp2_pkt_hd& header) {
    auto connection = std::shared_ptr<Connection>(
        new Connection(listener, socket, remote));
    if (!connection->Initialize(header)) return nullptr;
    bool tracked = false;
    try {
        listener.Associate(header.dcid, connection);
        listener.Associate(connection->core_->server_cid, connection);
        listener.sessions.emplace(connection.get(), connection);
        listener.environment.stats->OnConnectionAccepted();
        connection->stats_open_ = true;
        ++listener.tasks;
        tracked = true;
        net::co_spawn(connection->Reactor(), connection->Run(),
            [connection](std::exception_ptr error) {
                auto* owner = connection->listener_;
                connection->Close();
                owner->sessions.erase(connection.get());
                MaybeShrinkHashContainer(owner->sessions);
                --owner->tasks;
                owner->changed.cancel();
                if (error && !IsOperationCancelled(error))
                    LOG_ERROR("Hysteria connection task failed worker={}", owner->worker_id);
            });
    } catch (...) {
        connection->Close();
        listener.sessions.erase(connection.get());
        MaybeShrinkHashContainer(listener.sessions);
        if (tracked) --listener.tasks;
        throw;
    }
    return connection;
}

void Connection::Random(uint8_t* data, size_t length, const ngtcp2_rand_ctx*) {
    if (RAND_bytes(data, length) != 1) std::terminate();
}

int Connection::NewConnectionId(ngtcp2_conn*, ngtcp2_cid* cid, uint8_t* token,
    size_t length, void* user_data) {
    auto& self = *static_cast<Connection*>(user_data);
    if (RAND_bytes(cid->data, length) != 1) return NGTCP2_ERR_CALLBACK_FAILURE;
    EncodeWorkerServerCid(*cid, length, self.listener_->worker_id);
    if (RAND_bytes(token, NGTCP2_STATELESS_RESET_TOKENLEN) != 1)
        return NGTCP2_ERR_CALLBACK_FAILURE;
    try { self.listener_->Associate(*cid, self.shared_from_this()); }
    catch (...) { return NGTCP2_ERR_CALLBACK_FAILURE; }
    return 0;
}

int Connection::RemoveConnectionId(ngtcp2_conn*, const ngtcp2_cid* cid,
    void* user_data) {
    auto& self = *static_cast<Connection*>(user_data);
    self.listener_->Dissociate(*cid);
    std::erase(self.connection_ids_, ConnectionId(*cid));
    return 0;
}

int Connection::UpdateKey(ngtcp2_conn* conn, uint8_t* rx_secret,
    uint8_t* tx_secret, ngtcp2_crypto_aead_ctx* rx_ctx, uint8_t* rx_iv,
    ngtcp2_crypto_aead_ctx* tx_ctx, uint8_t* tx_iv,
    const uint8_t* current_rx, const uint8_t* current_tx, size_t secret_length,
    void*) {
    std::array<uint8_t, 64> rx_key{}, tx_key{};
    const int rc = ngtcp2_crypto_update_key(conn, rx_secret, tx_secret, rx_ctx,
        rx_key.data(), rx_iv, tx_ctx, tx_key.data(), tx_iv,
        current_rx, current_tx, secret_length);
    OPENSSL_cleanse(rx_key.data(), rx_key.size());
    OPENSSL_cleanse(tx_key.data(), tx_key.size());
    return rc;
}

int Connection::ReceiveTxKey(ngtcp2_conn*, ngtcp2_encryption_level level,
    void* user_data) {
    auto& self = *static_cast<Connection*>(user_data);
    return level == NGTCP2_ENCRYPTION_LEVEL_1RTT &&
           self.listener_->version == Version::V2 && !self.SetupHttp3()
        ? NGTCP2_ERR_CALLBACK_FAILURE : 0;
}

int Connection::ReceiveDatagram(ngtcp2_conn*, uint32_t flags,
    const uint8_t* data, size_t length, void* user_data) {
    auto& self = *static_cast<Connection*>(user_data);
    if ((flags & NGTCP2_DATAGRAM_FLAG_0RTT) || !self.authenticated_)
        return 0;
    auto message = ParseUdpMessage(self.listener_->version, {data, length});
    if (message) self.HandleUdpMessage(*message);
    return 0;
}

void Connection::InitializeBaseContext(const udp::endpoint& remote) {
    const auto& receiver = listener_->Receiver();
    base_context_.conn_id = session::NewID(listener_->worker_id);
    base_context_.worker_id = listener_->worker_id;
    base_context_.inbound.tag = receiver.inbound_tag;
    base_context_.inbound.accounting_key = receiver.accounting_key;
    if (const auto* route_tags = receiver.RouteInboundTags()) {
        base_context_.inbound.tags.reserve(route_tags->size());
        for (const auto& tag : *route_tags) base_context_.inbound.tags.emplace_back(tag);
    }
    const auto& local = core_->local;
    if (!local.address().is_unspecified()) {
        base_context_.inbound.local_endpoint =
            tcp::endpoint(iputil::NormalizeAddress(local.address()), local.port());
    }
    const auto source = iputil::NormalizeAddress(remote.address());
    base_context_.inbound.source_addr = source;
    base_context_.inbound.source_ip = iputil::AddressText(source).View();
    base_context_.inbound.source_port = remote.port();
}

bool Connection::Initialize(const ngtcp2_pkt_hd& header) {
    core_->server_cid.datalen = kServerConnectionIdLength;
    if (RAND_bytes(core_->server_cid.data, core_->server_cid.datalen) != 1)
        return false;
    EncodeWorkerServerCid(core_->server_cid, kServerConnectionIdLength, listener_->worker_id);
    ngtcp2_callbacks callbacks{};
    callbacks.recv_client_initial = ngtcp2_crypto_recv_client_initial_cb;
    callbacks.recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb;
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
    callbacks.path_validation = &PathValidated;
    callbacks.begin_path_validation = &PathValidationStarted;

    const auto& timeouts = listener_->environment.timeouts;
    ngtcp2_settings quic_settings;
    ngtcp2_settings_default(&quic_settings);
    quic_settings.initial_ts = Timestamp();
    quic_settings.cc_algo = NGTCP2_CC_ALGO_BBR;
    quic_settings.max_stream_window = kMaxStreamData;
    quic_settings.handshake_timeout =
        static_cast<ngtcp2_duration>(timeouts.HandshakeTimeout().count()) * NGTCP2_SECONDS;

    ngtcp2_transport_params parameters;
    ngtcp2_transport_params_default(&parameters);
    parameters.initial_max_stream_data_bidi_local = kMaxStreamData;
    parameters.initial_max_stream_data_bidi_remote = kMaxStreamData;
    parameters.initial_max_stream_data_uni = kMaxStreamData;
    parameters.initial_max_data = kMaxConnectionData;
    parameters.initial_max_streams_bidi = kMaxStreams;
    parameters.initial_max_streams_uni = 16;
    parameters.max_idle_timeout =
        static_cast<ngtcp2_duration>(timeouts.IdleTimeout().count()) * NGTCP2_SECONDS;
    parameters.max_datagram_frame_size = 65535;
    parameters.active_connection_id_limit = 8;
    parameters.original_dcid_present = 1;
    parameters.original_dcid = header.dcid;

    auto local = MakeAddress(core_->local);
    auto remote = MakeAddress(core_->remote);
    ngtcp2_path path{local, remote, &core_->path_binding};
    if (ngtcp2_conn_server_new(
            &core_->quic, &header.scid, &core_->server_cid, &path,
            header.version, &callbacks, &quic_settings, &parameters,
            QuicMemory::Ngtcp2(), this) != 0)
        return false;

    core_->conn_ref = {&GetConn, this};
    core_->ssl = SSL_new(listener_->ssl_context.get());
    if (!core_->ssl) return false;
    SSL_set_app_data(core_->ssl, &core_->conn_ref);
    SSL_set_accept_state(core_->ssl);
    ngtcp2_conn_set_tls_native_handle(core_->quic, core_->ssl);
    return true;
}

void Connection::SpawnOwned(net::awaitable<void> task) {
    tasks_->Spawn([](std::shared_ptr<Connection> owner, net::awaitable<void> request)
        -> net::awaitable<void> {
        try { co_await std::move(request); }
        catch (const std::exception& error) {
            if (!owner->closed_)
                LOG_CONN_DEBUG(owner->base_context_, "Hysteria request ended > {}", error.what());
        } catch (...) {
            if (!owner->closed_)
                LOG_CONN_DEBUG(owner->base_context_, "Hysteria request ended > unknown failure");
        }
    }(shared_from_this(), std::move(task)));
}

net::awaitable<void> Connection::Run() {
    std::exception_ptr failure;
    if (listener_->environment.active_sessions) ++*listener_->environment.active_sessions;
    try {
        co_await RunAwaitableTaskGroup(Reactor().get_executor(), [&](AwaitableTaskGroup& tasks) {
            tasks_ = &tasks;
            tasks.Spawn(WaitClosed());
            tasks.Spawn(ReservePhysicalAdmission());
            listener_->Pump(shared_from_this());
        });
    } catch (...) { failure = std::current_exception(); }
    Close();
    tasks_ = nullptr;
    core_.reset();
    if (listener_->environment.active_sessions) --*listener_->environment.active_sessions;
    if (failure) std::rethrow_exception(failure);
}

net::awaitable<void> Connection::WaitClosed() {
    if (!closed_) {
        auto [error] = co_await closed_signal_.async_receive(
            net::as_tuple(net::use_awaitable));
        (void)error;
    }
    Close();
    if (tasks_) tasks_->Cancel();
}

SocketState* Connection::OutputSocket(const ngtcp2_path& path) const noexcept {
    if (path.user_data != &core_->path_binding) return nullptr;
    auto local = EndpointFromAddress(path.local);
    return local ? listener_->Resolve(*local) : nullptr;
}

void Connection::PublishExpiry() noexcept {
    expiry_ = Expiry();
    listener_->ArmExpiry();
}

int Connection::PathValidationStarted(ngtcp2_conn*, uint32_t,
    const ngtcp2_path*, const ngtcp2_path*, void*) {
    return 0;
}

int Connection::PathValidated(ngtcp2_conn*, uint32_t,
    const ngtcp2_path* path, const ngtcp2_path*,
    ngtcp2_path_validation_result result, void* user_data) {
    auto& self = *static_cast<Connection*>(user_data);
    if (result != NGTCP2_PATH_VALIDATION_RESULT_SUCCESS || !path) return 0;
    auto local = EndpointFromAddress(path->local);
    auto remote = EndpointFromAddress(path->remote);
    if (local && remote) {
        self.core_->local = *local;
        self.core_->remote = *remote;
        try {
            LOG_CONN_DEBUG(self.base_context_,
                "QUIC path validated worker={} remote={}:{} path_evidence=challenge",
                self.listener_->worker_id,
                iputil::AddressText(remote->address()).View(), remote->port());
        } catch (...) {}
    }
    return 0;
}

bool Connection::Feed(SocketState& socket, const udp::endpoint& remote,
                      std::span<const uint8_t> packet, bool flush) {
    if (!core_ || closed_) return false;
    auto local_addr = MakeAddress(socket.local);
    auto remote_addr = MakeAddress(remote);
    ngtcp2_path path{local_addr, remote_addr, &core_->path_binding};
    ngtcp2_pkt_info packet_info{};
    const bool foreign_path = (socket.local != core_->local || remote != core_->remote);
    uint64_t packets_received = 0;
    if (foreign_path) {
        ngtcp2_conn_info info{};
        ngtcp2_conn_get_conn_info(core_->quic, &info);
        packets_received = info.pkt_recv;
    }
    in_ngtcp2_callback_ = true;
    const int result = ngtcp2_conn_read_pkt(
        core_->quic, &path, &packet_info, packet.data(), packet.size(), Timestamp());
    in_ngtcp2_callback_ = false;
    if (result != 0) {
        if (result != NGTCP2_ERR_DRAINING && result != NGTCP2_ERR_IDLE_CLOSE)
            listener_->environment.stats->OnError();
        Close();
        return false;
    }
    if (foreign_path) {
        ngtcp2_conn_info info{};
        ngtcp2_conn_get_conn_info(core_->quic, &info);
        if (info.pkt_recv == packets_received) {
            try {
                LOG_DEBUG("QUIC path packet rejected receiving_worker={} remote={}:{} reason=no-path-evidence",
                    listener_->worker_id, iputil::AddressText(remote.address()).View(), remote.port());
            } catch (...) {}
            return !closed_;
        }
        const auto* selected = ngtcp2_conn_get_path(core_->quic);
        auto selected_local = EndpointFromAddress(selected->local);
        auto selected_remote = EndpointFromAddress(selected->remote);
        if (selected_local && selected_remote &&
            (*selected_local != core_->local || *selected_remote != core_->remote)) {
            core_->local = *selected_local;
            core_->remote = *selected_remote;
            try {
                LOG_CONN_DEBUG(base_context_,
                    "QUIC path updated worker={} remote={}:{} path_evidence=reused",
                    listener_->worker_id,
                    iputil::AddressText(selected_remote->address()).View(),
                    selected_remote->port());
            } catch (...) {}
        }
    }
    if (flush) Flush();
    return !closed_;
}

void Connection::OnExpiry() {
    if (!core_ || closed_) return;
    const auto now = Timestamp();
    if (fragment_expiry_ <= now) ExpireUdpFragments(now);
    if (ngtcp2_conn_get_expiry(core_->quic) > now) {
        PublishExpiry();
        return;
    }
    in_ngtcp2_callback_ = true;
    const int result = ngtcp2_conn_handle_expiry(core_->quic, now);
    in_ngtcp2_callback_ = false;
    if (result != 0) {
        Close();
        return;
    }
    Flush();
}

net::awaitable<void> Connection::WriteStream(
    int64_t stream_id, buf::MultiBuffer payload) {
    const size_t bytes = payload.byte_size();
    for (;;) {
        std::shared_ptr<QuicStreamState> state;
        {
            if (!core_ || closed_)
                throw transport::LinkError(ErrorCode::CONNECTION_CLOSED);
            auto it = core_->streams.find(stream_id);
            if (it == core_->streams.end())
                throw transport::LinkError(ErrorCode::CONNECTION_CLOSED);
            state = it->second.state;
            state->CheckWriteOpen();
            if (bytes > kMaxStreamOutputBytes)
                throw transport::LinkError(ErrorCode::RESOURCE_EXHAUSTED);
            if (it->second.queued_bytes <= kMaxStreamOutputBytes - bytes) {
                if (bytes != 0) {
                    it->second.output.push_back(std::move(payload));
                }
                it->second.queued_bytes += bytes;
                Flush();
                co_return;
            }
        }
        // Only the stable state survives suspension, never a map iterator.
        // ACKs release retained buffers; packet transmission alone does not.
        co_await state->WaitWritable();
    }
}

void Connection::ConsumeStream(int64_t stream_id, size_t bytes) noexcept {
    if (!core_ || closed_) return;
    ngtcp2_conn_extend_max_stream_offset(core_->quic, stream_id, bytes);
    ngtcp2_conn_extend_max_offset(core_->quic, bytes);
    Flush();
}

void Connection::ShutdownStreamWrite(int64_t stream_id) noexcept {
    if (!core_ || closed_) return;
    auto it = core_->streams.find(stream_id);
    if (it == core_->streams.end()) return;
    it->second.fin_pending = true;
    Flush();
}

void Connection::CancelStream(int64_t stream_id) noexcept {
    if (!core_ || closed_) return;
    std::shared_ptr<QuicStreamState> state;
    {
        auto it = core_->streams.find(stream_id);
        if (it != core_->streams.end()) state = it->second.state;
    }
    if (state) state->RemoteReset();
    if (closed_) return;
    ngtcp2_conn_shutdown_stream(core_->quic, 0, stream_id, 0);
    Flush();
}

int Connection::AckStreamData(ngtcp2_conn*, int64_t stream_id, uint64_t offset,
    uint64_t length, void* user_data, void*) {
    auto& self = *static_cast<Connection*>(user_data);
    if (self.core_->http &&
        (!ngtcp2_is_bidi_stream(stream_id) ||
         self.core_->h3_requests.contains(stream_id)))
        return nghttp3_conn_add_ack_offset(
            self.core_->http, stream_id, length) == 0
            ? 0 : NGTCP2_ERR_CALLBACK_FAILURE;
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
    if (stream.acknowledged != previous_acknowledged)
        stream.state->NotifyWritable();
    return 0;
}

int Connection::OpenStream(ngtcp2_conn*, int64_t stream_id, void* user_data) {
    auto& self = *static_cast<Connection*>(user_data);
    if (!ngtcp2_is_bidi_stream(stream_id)) return 0;
    auto state = memory::AllocateShared<QuicStreamState>(
        self.Reactor(), stream_id,
        self.weak_from_this());
    auto [it, inserted] = self.core_->streams.try_emplace(
        stream_id, std::move(state));
    if (!inserted) return NGTCP2_ERR_CALLBACK_FAILURE;
    const auto version = self.listener_->version;
    if (version == Version::V1 && stream_id == 0) {
        self.SpawnOwned(self.RunV1Control(stream_id));
    } else if (version == Version::V2 && !self.authenticated_) {
        self.core_->h3_requests.try_emplace(stream_id);
    } else {
        it->second.raw = true;
        if (self.authenticated_) self.StartRawStream(stream_id, it->second);
    }
    return 0;
}

int Connection::CloseStream(ngtcp2_conn* conn, uint32_t flags, int64_t stream_id,
    uint64_t app_error_code, void* user_data, void*) {
    auto& self = *static_cast<Connection*>(user_data);
    if (self.core_->http &&
        (!ngtcp2_is_bidi_stream(stream_id) ||
         self.core_->h3_requests.contains(stream_id))) {
        const int result = nghttp3_conn_close_stream(
            self.core_->http, stream_id, app_error_code);
        if (result != 0 && result != NGHTTP3_ERR_STREAM_NOT_FOUND)
            return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    std::shared_ptr<QuicStreamState> state;
    if (auto it = self.core_->streams.find(stream_id);
        it != self.core_->streams.end()) {
        state = std::move(it->second.state);
        self.core_->streams.erase(it);
        MaybeShrinkHashContainer(self.core_->streams, 8);
    }
    self.core_->h3_requests.erase(stream_id);
    MaybeShrinkHashContainer(self.core_->h3_requests, 8);
    if (state) {
        if (conn != nullptr &&
            (flags & NGTCP2_STREAM_CLOSE_FLAG_APP_ERROR_CODE_SET) == 0) {
            state->OnStreamClosed();
        } else {
            state->RemoteReset();
        }
    }
    if (conn && ngtcp2_is_bidi_stream(stream_id) &&
        !ngtcp2_conn_is_local_stream(conn, stream_id))
        ngtcp2_conn_extend_max_streams_bidi(conn, 1);
    return 0;
}

int Connection::ResetStream(ngtcp2_conn*, int64_t stream_id, uint64_t,
    uint64_t, void* user_data, void*) {
    // RESET_STREAM is not stream_close: ngtcp2 may still borrow output for
    // the opposite direction until its actual close callback.
    auto& self = *static_cast<Connection*>(user_data);
    if (self.core_->http &&
        (!ngtcp2_is_bidi_stream(stream_id) ||
         self.core_->h3_requests.contains(stream_id))) {
        return nghttp3_conn_shutdown_stream_read(self.core_->http, stream_id) == 0
            ? 0 : NGTCP2_ERR_CALLBACK_FAILURE;
    }
    self.CancelStream(stream_id);
    return 0;
}

int Connection::StopSending(ngtcp2_conn*, int64_t stream_id, uint64_t,
    void* user_data, void*) {
    // This callback reports local read shutdown, not a peer STOP_SENDING.
    auto& self = *static_cast<Connection*>(user_data);
    if (self.core_->http &&
        (!ngtcp2_is_bidi_stream(stream_id) ||
         self.core_->h3_requests.contains(stream_id))) {
        return nghttp3_conn_shutdown_stream_read(self.core_->http, stream_id) == 0
            ? 0 : NGTCP2_ERR_CALLBACK_FAILURE;
    }
    self.CancelStream(stream_id);
    return 0;
}

void Connection::Flush() {
    if (!core_ || closed_ || in_ngtcp2_callback_) return;
    // ngtcp2 can retire streams while encoding packets as well as receiving
    // them. Credit and cancellation callbacks must not start a nested write.
    in_ngtcp2_callback_ = true;
    struct RefreshExpiry {
        Connection& connection;
        ~RefreshExpiry() {
            ngtcp2_conn_update_pkt_tx_time(connection.core_->quic, Timestamp());
            connection.in_ngtcp2_callback_ = false;
            connection.PublishExpiry();
        }
    } refresh{*this};
    std::array<uint8_t, NGTCP2_MAX_UDP_PAYLOAD_SIZE> packet;
    const size_t packet_limit = std::clamp<size_t>(
        ngtcp2_conn_get_send_quantum2(core_->quic) / packet.size(), 1, 64);
    // Every nonfatal write error removes one app/HTTP candidate until a
    // credit event. Include HTTP/3's three local unidirectional streams,
    // so exhausting blocked candidates still reaches a transport-only write.
    const size_t attempt_limit = packet_limit + core_->streams.size() +
        core_->h3_requests.size() + 3;
    size_t packets = 0;
    for (size_t attempt = 0;
         attempt < attempt_limit && packets < packet_limit; ++attempt) {
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
            http_data = stream_id >= 0;
        }
        if (!http_data && !core_->streams.empty()) {
            auto next = core_->streams.find(core_->next_output_stream);
            if (next == core_->streams.end()) next = core_->streams.begin();
            for (size_t remaining = core_->streams.size();
                 remaining != 0; --remaining) {
                auto current = next++;
                if (next == core_->streams.end()) next = core_->streams.begin();
                auto& [id, stream] = *current;
                if (!stream.state->Open() || stream.flow_blocked) continue;
                const bool has_unsent =
                    stream.output_offset < stream.queued_bytes;
                if (!has_unsent && !stream.fin_pending) continue;
                core_->next_output_stream = next->first;
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
        auto local = MakeAddress(core_->local);
        auto remote = MakeAddress(core_->remote);
        ngtcp2_path_storage write_path{};
        ngtcp2_path_storage_init(
            &write_path, local.addr, local.addrlen, remote.addr, remote.addrlen,
            &core_->path_binding);
        ngtcp2_pkt_info packet_info{};
        if (!core_->datagrams.empty()) {
            auto& datagram = core_->datagrams.front();
            ngtcp2_vec vector{datagram.data(), datagram.size()};
            int accepted_datagram = 0;
            const auto written = ngtcp2_conn_writev_datagram(
                core_->quic, &write_path.path, &packet_info, packet.data(), packet.size(),
                &accepted_datagram, NGTCP2_WRITE_DATAGRAM_FLAG_NONE, 0,
                &vector, 1, Timestamp());
            if (written < 0) {
                if (written == NGTCP2_ERR_INVALID_STATE) return;
                Close();
                return;
            }
            if (accepted_datagram) core_->datagrams.pop_front();
            if (written == 0) return;
            auto* output_socket = OutputSocket(write_path.path);
            auto output_remote = EndpointFromAddress(write_path.path.remote);
            if (!output_socket || !output_remote ||
                !listener_->Queue(*output_socket,
                    std::span<const uint8_t>(packet.data(), static_cast<size_t>(written)),
                    *output_remote, shared_from_this())) {
                Close();
                return;
            }
            ++packets;
            continue;
        }
        ngtcp2_ssize accepted = -1;
        uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_PADDING;
        if (fin) flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;
        const auto written = ngtcp2_conn_writev_stream(
            core_->quic, &write_path.path, &packet_info, packet.data(), packet.size(),
            &accepted, flags, stream_id, vectors.data(), vector_count, Timestamp());
        if (written == 0) return;
        if (written == NGTCP2_ERR_STREAM_DATA_BLOCKED ||
            written == NGTCP2_ERR_STREAM_SHUT_WR ||
            written == NGTCP2_ERR_STREAM_NOT_FOUND) {
            if (http_data) {
                if (written == NGTCP2_ERR_STREAM_DATA_BLOCKED)
                    nghttp3_conn_block_stream(core_->http, stream_id);
                else
                    nghttp3_conn_shutdown_stream_write(core_->http, stream_id);
            } else if (auto it = core_->streams.find(stream_id);
                       it != core_->streams.end()) {
                if (written == NGTCP2_ERR_STREAM_DATA_BLOCKED) {
                    it->second.flow_blocked = true;
                } else {
                    auto state = it->second.state;
                    state->RemoteReset();
                }
            }
            continue;
        }
        if (written < 0) {
            Close();
            return;
        }
        // A packet carrying only ACK/control frames has accepted == -1;
        // neither an application FIN nor HTTP/3's write offset can commit.
        if (accepted >= 0) {
            if (http_data) {
                if (nghttp3_conn_add_write_offset(
                        core_->http, stream_id,
                        static_cast<size_t>(accepted)) != 0) {
                    Close();
                    return;
                }
            } else if (auto it = core_->streams.find(stream_id);
                       it != core_->streams.end()) {
                it->second.output_offset += static_cast<size_t>(accepted);
                if (fin) it->second.fin_pending = false;
            }
        }
        auto* output_socket = OutputSocket(write_path.path);
        auto output_remote = EndpointFromAddress(write_path.path.remote);
        if (!output_socket || !output_remote ||
            !listener_->Queue(*output_socket,
                std::span<const uint8_t>(packet.data(), static_cast<size_t>(written)),
                *output_remote, shared_from_this())) {
            Close();
            return;
        }
        ++packets;
    }
}

void Connection::Close() noexcept {
    if (closed_) return;
    closed_ = true;
    ExpireUdpFragments(std::numeric_limits<ngtcp2_tstamp>::max());
    if (core_) {
        // Native QUIC still borrows output until Run drains I/O and destroys
        // Core. Closing only cancels application work and releases input.
        for (auto& [id, stream] : core_->streams) {
            (void)id;
            stream.state->RemoteReset();
        }
        auto udp_sessions = std::move(core_->udp_sessions);
        core_->udp_sessions.clear();
        for (auto& [session_id, session] : udp_sessions) {
            (void)session_id;
            session->Detach();
        }
        core_->datagrams.clear();
        core_->h3_requests.clear();
        listener_->DissociateAll(*this);
    }
    if (physical_ == PhysicalAdmission::Pending) (void)physical_ready_.try_send(IoErrorCode{});
    if (stats_open_) {
        listener_->environment.stats->OnConnectionClosed();
        stats_open_ = false;
    }
    stream_sink_.reset();
    online_session_.reset();
    physical_reservation_ = {};
    (void)closed_signal_.try_send(IoErrorCode{});
}

net::awaitable<void> Connection::ReservePhysicalAdmission() {
    auto admission = co_await listener_->environment.limiter->ReservePhysical(
        base_context_.inbound.tag, base_context_.inbound.source_ip,
        base_context_.inbound.HasProxyProtocolClientIP());
    const auto reject = admission.reason;
    if (closed_) co_return;
    if (reject != ConnectionLimiter::RejectReason::NONE) {
        LOG_CONN_DEBUG(base_context_, "connection rejected from {}:{} > {}",
                       base_context_.inbound.source_ip, base_context_.inbound.source_port,
                       ConnectionLimiter::RejectReasonToString(reject));
        LOG_ACCESS(FormatAccessLog(base_context_, AccessStatus::Rejected,
                                  ConnectionLimiter::RejectReasonToString(reject)));
        listener_->environment.stats->OnError();
        physical_ = PhysicalAdmission::Rejected;
        (void)physical_ready_.try_send(IoErrorCode{});
        Refuse();
        co_return;
    }
    physical_reservation_ = std::move(admission.reservation);
    physical_ = PhysicalAdmission::Admitted;
    (void)physical_ready_.try_send(IoErrorCode{});
}

// Physical admission refused: send one CONNECTION_CLOSE with the transport
// error CONNECTION_REFUSED (RFC 9000 §20.1, the server refusing a new
// connection), then drop all state as TCP closes a refused socket. ngtcp2
// encodes it at the handshake levels the peer can read (RFC 9000 §10.2.3).
// No closing period is kept: a retransmission finds no connection.
void Connection::Refuse() noexcept {
    if (closed_) return;
    if (core_ && core_->quic &&
        !ngtcp2_conn_in_closing_period(core_->quic) &&
        !ngtcp2_conn_in_draining_period(core_->quic)) {
        ngtcp2_ccerr error;
        ngtcp2_ccerr_default(&error);
        ngtcp2_ccerr_set_transport_error(&error, NGTCP2_CONNECTION_REFUSED, nullptr, 0);
        std::array<uint8_t, NGTCP2_MAX_UDP_PAYLOAD_SIZE> packet{};
        auto local = MakeAddress(core_->local);
        auto remote = MakeAddress(core_->remote);
        ngtcp2_path path{local, remote, &core_->path_binding};
        ngtcp2_pkt_info packet_info{};
        const auto written = ngtcp2_conn_write_connection_close(
            core_->quic, &path, &packet_info, packet.data(), packet.size(),
            &error, Timestamp());
        if (written > 0) {
            try {
                if (auto* socket = OutputSocket(path))
                    (void)listener_->Queue(*socket,
                        std::span<const uint8_t>(packet.data(), static_cast<size_t>(written)),
                        core_->remote, shared_from_this(), true);
            } catch (const std::bad_alloc&) {
                // The close frame is advisory; state is dropped regardless.
            }
        }
    }
    Close();
}

net::awaitable<Connection::AdmitResult> Connection::AdmitConnection(
    std::string_view credential) {
    auto auth_hash = HashCredential(credential);
    struct CleanseAuthHash {
        std::array<uint8_t, 32>& hash;
        ~CleanseAuthHash() noexcept { OPENSSL_cleanse(hash.data(), hash.size()); }
    } cleanse_auth_hash{auth_hash};
    auto* limiter = listener_->environment.limiter;
    while (physical_ == PhysicalAdmission::Pending && !closed_) {
        auto [error] = co_await physical_ready_.async_receive(
            net::as_tuple(net::use_awaitable));
        if (error) co_return AdmitResult::Limited;
    }
    if (closed_ || physical_ != PhysicalAdmission::Admitted)
        co_return AdmitResult::Limited;
    const auto credential_check = co_await proxy::VerifyInboundCredential(
        limiter, base_context_, proxyman::inbound::UserProtocol::Hysteria, auth_hash);
    if (credential_check.error != ErrorCode::OK) {
        listener_->environment.stats->OnError();
        co_return AdmitResult::Limited;
    }
    if (closed_) co_return AdmitResult::Limited;
    const auto& receiver = listener_->Receiver();
    auto user = proxyman::inbound::UserStore::FindHysteriaUser(
        receiver.inbound_tag, auth_hash);
    if (!user) {
        co_await proxy::RecordInboundAuthFailure(
            limiter, base_context_, "no matching credential", credential_check.key);
        listener_->environment.stats->OnError();
        co_return AdmitResult::AuthFailed;
    }
    const auto profile = user->profile;
    user.reset();
    proxy::BindAuthenticatedInbound(base_context_, profile, std::nullopt);
    auto session = co_await proxy::AdmitAuthenticatedInbound(
        *listener_->environment.tracker, base_context_, profile);
    if (!session) co_return AdmitResult::DeviceLimited;
    if (closed_) co_return AdmitResult::Limited;
    online_session_.emplace(std::move(*session));
    stream_sink_ = listener_->environment.handler->NewAuthenticatedStreamSink(
        Reactor(), *listener_->environment.dispatcher, *listener_->environment.stats,
        *listener_->environment.request_load, listener_->environment.timeouts,
        base_context_, physical_reservation_.FamilyLease());
    authenticated_ = true;
    co_return AdmitResult::Admitted;
}

void Connection::OnStreamData(
    uint32_t flags, int64_t stream_id, std::span<const uint8_t> data) {
    const bool fin = (flags & NGTCP2_STREAM_DATA_FLAG_FIN) != 0;
    auto it = core_->streams.find(stream_id);
    if (listener_->version == Version::V2 &&
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
    auto& stream = it->second;
    if (!stream.state->PushInput(data, fin)) {
        // ngtcp2 has already delivered these bytes; its stream teardown only
        // credits bytes not delivered to the application.
        ConsumeStream(stream_id, data.size());
        CancelStream(stream_id);
        return;
    }
    if (stream.raw && authenticated_ && !stream.delivered)
        StartRawStream(stream_id, stream);
}

// v2 request streams go to the inbound handler as soon as they open. A v1
// stream is classified by its first byte: zero is a TCP request, read by the
// inbound handler; otherwise it opens a UDP session, a transport concern.
void Connection::StartRawStream(int64_t stream_id, StreamRecord& stream) {
    if (stream.delivered) return;
    if (listener_->version == Version::V1) {
        const auto& input = stream.state->PendingInput();
        const auto front = input.FrontSpan();
        if (front.empty()) return;
        if (front[0] != 0) {
            const size_t inspect_bytes =
                std::min(input.byte_size(), kMaxStreamHeaderBytes);
            auto prefix = input.PrefixSpan(inspect_bytes);
            memory::ThreadLocalVector<uint8_t> header;
            if (prefix.empty()) {
                header.resize(inspect_bytes);
                (void)input.CopyPrefixTo(header);
                prefix = header;
            }
            auto request = ParseV1Request(prefix);
            if (!request) {
                if (request.error() != ProtocolError::Incomplete ||
                    input.byte_size() >= kMaxStreamHeaderBytes)
                    CancelStream(stream_id);
                return;
            }
            OpenV1UdpSession(stream_id, stream, request->header_bytes);
            return;
        }
    }
    stream.delivered = true;
    SpawnOwned(DeliverStream(std::make_unique<QuicStream>(stream.state)));
}

void Connection::OpenV1UdpSession(
    int64_t stream_id, StreamRecord& stream, size_t header_bytes) {
    const uint32_t session_id = next_udp_session_id_++;
    if (session_id == 0 || core_->udp_sessions.size() >= kMaxUdpSessions) {
        CancelStream(stream_id);
        return;
    }
    stream.delivered = true;
    stream.state->DiscardInput(header_bytes);
    const auto response = EncodeV1Response(true, session_id, "");
    stream.output.push_back(CopyPacket(response));
    stream.queued_bytes += response.size();
    Flush();
}

net::awaitable<void> Connection::DeliverStream(std::unique_ptr<AsyncStream> stream) {
    auto sink = stream_sink_;
    if (!sink) co_return;
    co_await sink->OnInboundTransportStream(std::move(stream), InboundTransportMetadata{});
}

net::awaitable<void> Connection::RunV1Control(int64_t stream_id) {
    auto it = core_->streams.find(stream_id);
    if (it == core_->streams.end()) co_return;
    auto state = it->second.state;
    constexpr size_t kMaxHelloBytes = kMaxAuthLength + 32;
    memory::ThreadLocalVector<uint8_t> hello_bytes;
    tl::expected<V1ClientHello, ProtocolError> hello =
        tl::unexpected(ProtocolError::Incomplete);
    while (!hello) {
        auto chunk = co_await state->ReadMultiBuffer();
        const size_t bytes = chunk.byte_size();
        if (bytes == 0 || bytes > kMaxHelloBytes - hello_bytes.size()) co_return;
        const size_t offset = hello_bytes.size();
        hello_bytes.resize(offset + bytes);
        (void)chunk.CopyPrefixTo(std::span<uint8_t>(hello_bytes.data() + offset, bytes));
        chunk.clear();
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
        true, listener_->download_bytes_per_second,
        listener_->upload_bytes_per_second, "");
    co_await state->WriteMultiBuffer(CopyPacket(response));
    if (closed_) co_return;
    memory::ThreadLocalVector<int64_t> waiting;
    for (const auto& [id, candidate] : core_->streams) {
        if (candidate.raw && !candidate.delivered) waiting.push_back(id);
    }
    for (const auto id : waiting) {
        if (closed_) co_return;
        if (auto found = core_->streams.find(id); found != core_->streams.end())
            StartRawStream(id, found->second);
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
            QuicMemory::Nghttp3(), this) != 0) return false;
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
    const std::string_view header_value{
        reinterpret_cast<const char*>(value_buffer.base), value_buffer.len};
    if (token == NGHTTP3_QPACK_TOKEN__METHOD) it->second.method.assign(header_value);
    else if (token == NGHTTP3_QPACK_TOKEN__PATH) it->second.path.assign(header_value);
    else if (token == NGHTTP3_QPACK_TOKEN__AUTHORITY)
        it->second.authority.assign(header_value);
    else if (header_name == "hysteria-auth") it->second.auth.assign(header_value);
}

void Connection::SubmitHttpStatus(
    int64_t stream_id, std::string_view status, bool accepted) {
    if (closed_ || !core_->http) return;
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
    if (authenticated_ || admitting_ || request.method != "POST" ||
        request.path != "/auth" || request.authority != "hysteria" ||
        request.auth.empty()) {
        SubmitHttpStatus(stream_id, "404", false);
        co_return;
    }
    admitting_ = true;
    const auto result = co_await AdmitConnection(request.auth);
    admitting_ = false;
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

void Connection::ExpireUdpFragments(ngtcp2_tstamp now) noexcept {
    if (!fragments_.empty() && fragment_expiry_ > now) return;
    fragment_expiry_ = std::numeric_limits<ngtcp2_tstamp>::max();
    for (auto it = fragments_.begin(); it != fragments_.end();) {
        if (it->second.expires_at <= now) {
            it = fragments_.erase(it);
        } else {
            fragment_expiry_ = std::min(fragment_expiry_, it->second.expires_at);
            ++it;
        }
    }
    if (fragments_.empty()) {
        decltype(fragments_) released;
        fragments_.swap(released);
    }
}

void Connection::HandleUdpMessage(const UdpMessage& message) {
    if (message.fragment_count == 1) {
        if (message.target.IsValid())
            DeliverUdpPacket(message.session_id, message.target, message.payload);
        return;
    }
    const auto now = Timestamp();
    if (fragment_expiry_ <= now) ExpireUdpFragments(now);
    const uint64_t key =
        (static_cast<uint64_t>(message.session_id) << 16) | message.packet_id;
    auto it = fragments_.find(key);
    if (it == fragments_.end()) {
        if (message.fragment_id == 0 && !message.target.IsValid()) return;
        if (fragments_.size() >= kMaxPendingFragments) {
            fragments_.erase(fragments_.begin());
        }
        it = fragments_.try_emplace(key).first;
        it->second.count = message.fragment_count;
        it->second.deadline = UdpFragmentDeadline(now, kUdpFragmentLifetime);
        it->second.expires_at = std::min(it->second.deadline,
            UdpFragmentDeadline(now, kUdpFragmentIdleTimeout));
        fragment_expiry_ = std::min(fragment_expiry_, it->second.expires_at);
    }
    auto& pending = it->second;
    if ((message.fragment_id == 0 && !message.target.IsValid()) ||
        pending.count != message.fragment_count ||
        message.fragment_id >= pending.count ||
        pending.received_fragments.test(message.fragment_id) ||
        pending.bytes > kMaxUdpPayloadLength - message.payload.size()) {
        fragments_.erase(it);
        ExpireUdpFragments(now);
        return;
    }
    if (message.fragment_id == 0) pending.target = message.target;
    // Header-only fragments still satisfy an index; do not allocate a payload
    // slot for them or confuse their empty data with a missing fragment.
    if (!message.payload.empty()) {
        pending.payloads.emplace_back(message.payload.begin(), message.payload.end());
        // At most count distinct indices can arrive, and count fits uint8_t.
        pending.payload_slots[message.fragment_id] =
            static_cast<uint8_t>(pending.payloads.size());
    }
    pending.received_fragments.set(message.fragment_id);
    pending.bytes += message.payload.size();
    ++pending.received;
    pending.expires_at = std::min(pending.deadline,
        UdpFragmentDeadline(now, kUdpFragmentIdleTimeout));
    if (pending.received != pending.count) return;
    if (!pending.target.IsValid()) {
        fragments_.erase(it);
        ExpireUdpFragments(now);
        return;
    }
    memory::ThreadLocalVector<uint8_t> payload;
    payload.reserve(pending.bytes);
    for (size_t id = 0; id < pending.count; ++id) {
        const auto slot = pending.payload_slots[id];
        if (slot == 0) continue;
        const auto& fragment = pending.payloads[slot - 1];
        payload.insert(payload.end(), fragment.begin(), fragment.end());
    }
    const TargetAddress target = std::move(pending.target);
    fragments_.erase(it);
    ExpireUdpFragments(now);
    DeliverUdpPacket(message.session_id, target, payload);
}

void Connection::DeliverUdpPacket(
    uint32_t session_id, const TargetAddress& target,
    std::span<const uint8_t> payload) {
    if (auto it = core_->udp_sessions.find(session_id);
        it != core_->udp_sessions.end()) {
        (void)it->second->Push(target, payload);
        return;
    }
    if (core_->udp_sessions.size() >= kMaxUdpSessions) return;
    auto session = std::make_unique<UdpSessionStream>(
        Reactor(), session_id, target,
        weak_from_this());
    if (!session->Push(target, payload)) return;
    core_->udp_sessions.emplace(session_id, session.get());
    SpawnOwned(DeliverStream(std::move(session)));
}

bool Connection::SendUdpMessage(
    uint32_t session_id, const TargetAddress& target,
    std::span<const uint8_t> payload) {
    if (closed_ || !target.IsValid() ||
        payload.size() > kMaxUdpPayloadLength) return false;
    if (!core_ || !core_->quic) return false;
    const auto* parameters = ngtcp2_conn_get_remote_transport_params2(core_->quic);
    if (!parameters) return false;
    const auto frame_budget = std::min<uint64_t>(
        parameters->max_datagram_frame_size, kMaxUdpMessageSize + kUdpDatagramFrameOverhead);
    if (frame_budget < 2) return false;
    // 消息至多 1100B；LEN 在 63B 边界由一字节增为两字节。
    const auto message_budget = static_cast<size_t>(
        frame_budget <= 65 ? frame_budget - 2 : frame_budget - kUdpDatagramFrameOverhead);
    const auto version = listener_->version;
    const auto header_size = UdpMessageHeaderSize(version, target);
    if (!header_size || *header_size > message_budget) return false;
    const size_t fragment_payload = message_budget - *header_size;
    if (!payload.empty() && fragment_payload == 0) return false;
    const size_t fragments = payload.empty()
        ? 1 : 1 + (payload.size() - 1) / fragment_payload;
    if (fragments > std::numeric_limits<uint8_t>::max()) return false;
    if (core_->datagrams.size() >= kMaxQueuedDatagrams ||
        fragments > kMaxQueuedDatagrams - core_->datagrams.size()) return false;
    const size_t initial_datagrams = core_->datagrams.size();
    UdpMessage message{
        .session_id = session_id,
        .packet_id = next_udp_packet_id_++,
        .fragment_count = static_cast<uint8_t>(fragments),
        .target = target,
        .payload = {},
    };
    try {
        for (size_t index = 0; index < fragments; ++index) {
            const size_t offset = index * fragment_payload;
            message.fragment_id = static_cast<uint8_t>(index);
            message.payload = payload.subspan(
                offset, std::min(fragment_payload, payload.size() - offset));
            auto encoded = EncodeUdpMessage(version, message);
            if (!encoded) {
                while (core_->datagrams.size() > initial_datagrams)
                    core_->datagrams.pop_back();
                return false;
            }
            core_->datagrams.push_back(std::move(*encoded));
        }
    } catch (...) {
        while (core_->datagrams.size() > initial_datagrams)
            core_->datagrams.pop_back();
        throw;
    }
    Flush();
    return true;
}

void Connection::CloseUdpSession(uint32_t session_id) noexcept {
    if (core_) {
        core_->udp_sessions.erase(session_id);
        MaybeShrinkHashContainer(core_->udp_sessions, 8);
    }
}

HysteriaIngress::HysteriaIngress(
    uint32_t worker_id_value, net::io_context& io_value,
    app::DatagramSessionEnvironment environment_value)
    : environment(std::move(environment_value)),
      worker_id(worker_id_value), io(io_value),
      changed(io, std::chrono::steady_clock::time_point::max()), expiry(io) {
    const auto* settings = GetSettings(*environment.prepared);
    if (!settings) throw std::invalid_argument("missing Hysteria settings");
    version = settings->version;
    upload_bytes_per_second = settings->upload_bytes_per_second;
    download_bytes_per_second = settings->download_bytes_per_second;
    ssl_context = BuildSslContext(Receiver().stream_settings, version);
    if (!ssl_context) throw std::invalid_argument("invalid Hysteria TLS settings");
}

HysteriaIngress::~HysteriaIngress() noexcept { RequestStop(); }

void HysteriaIngress::Spawn(net::awaitable<void> task) {
    ++tasks;
    try {
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
    } catch (...) {
        --tasks;
        throw;
    }
}

bool HysteriaIngress::Queue(SocketState& socket, std::span<const uint8_t> data,
                            udp::endpoint remote, std::shared_ptr<Connection> connection,
                            bool terminal) {
    if (stopping || !socket.socket || !socket.socket->is_open()) return false;
    if (socket.output.empty()) {
        IoErrorCode error;
        (void)socket.socket->send_to(net::buffer(data.data(), data.size()), remote, 0, error);
        if (!error) return true;
        if (error == net::error::operation_aborted) return false;
        if (error != net::error::would_block && error != net::error::try_again) {
            return true;
        }
    }
    if (socket.output.size() >= kMaxQueuedSocketPackets) return false;
    socket.output.push_back({
        memory::ByteVector(data.begin(), data.end()),
        std::move(remote), std::move(connection), terminal});
    (void)socket.changed.try_send(IoErrorCode{});
    return true;
}

void HysteriaIngress::Associate(
    const ngtcp2_cid& cid, std::shared_ptr<Connection> connection) {
    const auto id = ConnectionId(cid);
    if (std::find(connection->connection_ids_.begin(), connection->connection_ids_.end(), id) ==
        connection->connection_ids_.end()) {
        if (connection->connection_ids_.size() >= 32)
            throw std::runtime_error("QUIC CID capacity exceeded");
        connection->connection_ids_.push_back(id);
    }
    auto [it, inserted] = connections.emplace(id, connection);
    if (!inserted && it->second != connection)
        throw std::runtime_error("QUIC local CID collision");
}

void HysteriaIngress::Dissociate(const ngtcp2_cid& cid) noexcept {
    connections.erase(ConnectionId(cid));
    MaybeShrinkHashContainer(connections);
}

void HysteriaIngress::DissociateAll(Connection& connection) noexcept {
    for (const auto& id : connection.connection_ids_) {
        connections.erase(id);
    }
    connection.connection_ids_.clear();
    MaybeShrinkHashContainer(connections);
}

SocketState* HysteriaIngress::Resolve(const udp::endpoint& local) noexcept {
    for (auto& [key, socket] : sockets) {
        (void)key;
        if (socket->local == local && socket->socket && socket->socket->is_open())
            return socket.get();
    }
    return nullptr;
}

void HysteriaIngress::Enqueue(const std::shared_ptr<Connection>& connection,
                              const std::shared_ptr<SocketState>& socket,
                              const udp::endpoint& remote,
                              memory::ThreadLocalVector<uint8_t> bytes) {
    if (!connection || !connection->core_ || connection->Closed()) {
        return;
    }
    auto& core = *connection->core_;
    if (core.inbox.size() >= 64 || bytes.size() > 256 * 1024 - core.inbox_bytes)
        return;
    core.inbox_bytes += bytes.size();
    core.inbox.push_back({socket, remote, std::move(bytes)});
    if (core.pump_scheduled) return;
    core.pump_scheduled = true;
    net::post(io, [this, connection] {
        if (connection->Closed()) return;
        Pump(connection);
    });
}

void HysteriaIngress::Pump(const std::shared_ptr<Connection>& connection) {
    if (!connection->core_ || !connection->core_->quic || !connection->tasks_ ||
        connection->Closed()) {
        return;
    }
    auto& core = *connection->core_;
    core.pump_scheduled = false;
    bool fed = false;
    while (!core.inbox.empty() && !connection->Closed()) {
        auto packet = std::move(core.inbox.front());
        core.inbox.pop_front();
        core.inbox_bytes -= packet.bytes.size();
        fed = true;
        (void)connection->Feed(*packet.socket, packet.remote, packet.bytes, false);
    }
    if (core.inbox.empty()) {
        memory::ThreadLocalDeque<Connection::Core::PendingInputPacket>{
            core.inbox.get_allocator()}.swap(core.inbox);
    }
    if (fed && !connection->Closed()) {
        connection->Flush();
    }
}

net::awaitable<void> HysteriaIngress::ReceiveLoop(std::shared_ptr<SocketState> socket) {
    ::detail::UdpReceiveBuffer receive_buffer;
    while (!stopping && socket->socket && socket->socket->is_open()) {
        receive_buffer.Release();
        auto [wait_error] = co_await socket->socket->async_wait(
            udp::socket::wait_read, net::as_tuple(net::use_awaitable));
        if (wait_error == net::error::operation_aborted || stopping ||
            !socket->socket || !socket->socket->is_open()) {
            co_return;
        }
        if (wait_error) continue;
        try {
            IoErrorCode error;
            const size_t available = socket->socket->available(error);
            if (error || available == 0 || available > kMaxPacketSize) {
                std::array<uint8_t, 1> discard{};
                (void)socket->socket->receive_from(
                    net::buffer(discard), socket->remote, 0, error);
                if (error == net::error::operation_aborted) co_return;
                continue;
            }
            const auto storage = receive_buffer.Prepare(available);
            if (storage.size() == 0) {
                std::array<uint8_t, 1> discard{};
                (void)socket->socket->receive_from(
                    net::buffer(discard), socket->remote, 0, error);
                if (error == net::error::operation_aborted) co_return;
                continue;
            }
            const size_t bytes = socket->socket->receive_from(
                storage, socket->remote, MSG_TRUNC, error);
            if (error == net::error::operation_aborted) co_return;
            if (error || bytes == 0 || bytes > storage.size()) continue;
            const auto packet = receive_buffer.Data(bytes);
            ngtcp2_version_cid version_cid{};
            if (ngtcp2_pkt_decode_version_cid(
                    &version_cid, packet.data(), packet.size(),
                    kServerConnectionIdLength) != 0)
                continue;
            if (version_cid.dcidlen > NGTCP2_MAX_CIDLEN) continue;
            const ConnectionId cid(version_cid.dcid, version_cid.dcidlen);
            auto found = connections.find(cid);
            std::shared_ptr<Connection> connection =
                found == connections.end() ? nullptr : found->second;
            if (!connection) {
                if ((packet[0] & 0x80) == 0) continue;
                if (connections.size() >= kMaxConnections) {
                    LOG_DEBUG("Hysteria listener connection capacity reached worker={}", worker_id);
                    continue;
                }
                ngtcp2_pkt_hd header{};
                if (ngtcp2_accept(&header, packet.data(), packet.size()) != 0) continue;
                connection = Connection::Create(*this, *socket, socket->remote, header);
                if (!connection) continue;
            }
            if (connection && connection->core_ && connection->core_->quic &&
                connection->core_->inbox.empty() && !connection->Closed() &&
                (connection->tasks_ || (packet[0] & 0x80) != 0)) {
                (void)connection->Feed(*socket, socket->remote, packet, true);
            } else {
                Enqueue(connection, socket, socket->remote,
                        memory::ThreadLocalVector<uint8_t>(packet.begin(), packet.end()));
            }
        } catch (const std::bad_alloc&) {
            if (stopping) co_return;
        } catch (const std::exception& failure) {
            if (stopping) co_return;
            try { LOG_DEBUG("Hysteria packet dropped worker={} reason={}", worker_id, failure.what()); }
            catch (...) {}
        } catch (...) {
            if (stopping) co_return;
        }
    }
}

net::awaitable<void> HysteriaIngress::SendLoop(std::shared_ptr<SocketState> socket) {
    while (!stopping && socket->socket && socket->socket->is_open()) {
        if (socket->output.empty()) {
            auto [error] = co_await socket->changed.async_receive(
                net::as_tuple(net::use_awaitable));
            if (error && stopping) co_return;
            continue;
        }
        auto packet = std::move(socket->output.front());
        socket->output.pop_front();
        if (stopping || (packet.connection && packet.connection->Closed() && !packet.terminal)) {
            continue;
        }
        auto [error, bytes] = co_await socket->socket->async_send_to(
            net::buffer(packet.data), packet.remote,
            net::as_tuple(net::use_awaitable));
        (void)bytes;
        if (error == net::error::operation_aborted) co_return;
    }
}

void HysteriaIngress::ArmExpiry() {
    ngtcp2_tstamp nearest = std::numeric_limits<ngtcp2_tstamp>::max();
    for (const auto& [raw, connection] : sessions) {
        (void)raw;
        if (!connection->Closed())
            nearest = std::min(nearest, connection->expiry_);
    }
    const auto expiry_time = ExpiryTimePoint(nearest);
    if (expiry_time == std::chrono::steady_clock::time_point::max()) {
        expiry.expires_at(std::chrono::steady_clock::time_point::max());
        return;
    }
    expiry.expires_at(expiry_time);
    if (!expiry_running) {
        expiry_running = true;
        Spawn(ExpiryLoop());
    }
}

net::awaitable<void> HysteriaIngress::ExpiryLoop() {
    while (!stopping) {
        auto [error] = co_await expiry.async_wait(
            net::as_tuple(net::use_awaitable));
        if (error == net::error::operation_aborted) {
            if (stopping) break;
            continue;
        }
        const auto now = Timestamp();
        memory::ThreadLocalVector<std::shared_ptr<Connection>> due;
        for (const auto& [raw, connection] : sessions) {
            (void)raw;
            if (!connection->Closed() && connection->expiry_ <= now)
                due.push_back(connection);
        }
        for (auto& connection : due) {
            connection->expiry_ = std::numeric_limits<ngtcp2_tstamp>::max();
            connection->OnExpiry();
        }

        ngtcp2_tstamp nearest =
            std::numeric_limits<ngtcp2_tstamp>::max();
        for (const auto& [raw, connection] : sessions) {
            (void)raw;
            if (!connection->Closed())
                nearest = std::min(nearest, connection->expiry_);
        }
        const auto expiry_time = ExpiryTimePoint(nearest);
        if (expiry_time == std::chrono::steady_clock::time_point::max()) break;
        expiry.expires_at(expiry_time);
    }
    expiry_running = false;
}

HysteriaIngress::SocketPtr HysteriaIngress::MakeSocket() {
    return memory::AllocateShared<udp::socket>(io);
}

HysteriaIngress::SocketPtr HysteriaIngress::AttachSocket(
    std::string_view socket_key, SocketPtr socket) {
    if (!socket || !socket->is_open() || started || stopping)
        return {};
    const auto* coordinator = GroupCoordinator::ForContext(io);
    const uint32_t worker_count = coordinator ? coordinator->WorkerCount() : 1;
    (void)AttachQuicReuseportBpf(socket->native_handle(), worker_count);
    auto state = memory::AllocateShared<SocketState>(io);
    state->socket = std::move(socket);
    state->key.assign(socket_key);
    IoErrorCode error;
    state->local = state->socket->local_endpoint(error);
    if (error) return {};
    state->socket->non_blocking(true, error);
    if (error) return {};
    auto [it, inserted] = sockets.try_emplace(state->key, state);
    return inserted ? it->second->socket : SocketPtr{};
}

void HysteriaIngress::Start() {
    if (started || stopping) return;
    started = true;
    for (auto& [key, socket] : sockets) {
        (void)key;
        Spawn(ReceiveLoop(socket));
        Spawn(SendLoop(socket));
    }
}

void HysteriaIngress::RequestStop() noexcept {
    if (stopping) return;
    stopping = true;
    IoErrorCode ignored;
    expiry.cancel();
    changed.cancel();
    for (auto& [key, socket] : sockets) {
        (void)key;
        socket->changed.cancel();
        if (socket->socket) socket->socket->close(ignored);
    }
    for (auto& [owner, connection] : sessions) {
        (void)owner;
        connection->Close();
    }
}

net::awaitable<void> HysteriaIngress::AsyncJoin() {
    RequestStop();
    while (tasks != 0) {
        auto [error] = co_await changed.async_wait(
            net::as_tuple(net::use_awaitable));
        (void)error;
    }
}

QuicStreamState::QuicStreamState(
    net::io_context& io_context,
    int64_t stream_id,
    std::weak_ptr<Connection> owner)
    : io_context_(io_context)
    , stream_id_(stream_id)
    , owner_(std::move(owner))
    , input_signal_(io_context.get_executor(), 1) {}

bool QuicStreamState::PushInput(std::span<const uint8_t> data, bool fin) {
    if (cancelled_ || input_done_ ||
        data.size() > kMaxQueuedInputBytes -
            std::min(input_.byte_size(), kMaxQueuedInputBytes)) {
        return false;
    }
    if (!buf::AppendSpanToMultiBuffer(data, input_)) return false;
    input_done_ = fin;
    WakeReader();
    return true;
}

void QuicStreamState::DiscardInput(size_t bytes) noexcept {
    AcknowledgeInput(input_.DropPrefixBytes(bytes));
}

void QuicStreamState::AcknowledgeInput(size_t bytes) noexcept {
    if (bytes == 0) return;
    if (auto owner = owner_.lock()) owner->ConsumeStream(stream_id_, bytes);
}

void QuicStreamState::OnStreamClosed() noexcept {
    auto owner = std::exchange(owner_, {}).lock();
    const auto stream_id = stream_id_;
    const size_t unread = input_.byte_size();
    input_done_ = true;
    write_done_ = true;
    WakeReader();
    NotifyWritable();
    // The buffered tail may still be drained, but must not retain connection
    // credit or acknowledge it twice after the transport stream is gone.
    if (owner && unread != 0) owner->ConsumeStream(stream_id, unread);
}

void QuicStreamState::RemoteReset() noexcept {
    Abort(false);
}

void QuicStreamState::Cancel() noexcept {
    Abort(true);
}

void QuicStreamState::Abort(bool cancel_transport) noexcept {
    if (cancelled_) return;
    auto owner = std::exchange(owner_, {}).lock();
    const auto stream_id = stream_id_;
    const size_t unread = input_.byte_size();
    cancelled_ = true;
    input_done_ = true;
    write_done_ = true;
    input_.clear();
    WakeReader();
    NotifyWritable();
    cancellation_.Stop();
    if (owner) {
        if (cancel_transport) owner->CancelStream(stream_id);
        if (unread != 0) owner->ConsumeStream(stream_id, unread);
    }
}

net::awaitable<size_t> QuicStreamState::Read(net::mutable_buffer buffer) {
    for (;;) {
        if (!input_.empty()) {
            const size_t bytes = input_.ConsumePrefixTo(
                {static_cast<uint8_t*>(buffer.data()), buffer.size()});
            input_.ReleaseIfIdle();
            AcknowledgeInput(bytes);
            co_return bytes;
        }
        if (cancelled_)
            throw transport::LinkError(ErrorCode::CANCELLED);
        if (input_done_) co_return 0;
        auto [error] = co_await input_signal_.async_receive(
            net::as_tuple(net::use_awaitable));
        if (error == net::experimental::error::channel_cancelled)
            error = net::error::operation_aborted;
        if (error)
            throw IoSystemError(error, "QUIC stream input cancelled");
    }
}

net::awaitable<buf::MultiBuffer> QuicStreamState::ReadMultiBuffer() {
    for (;;) {
        if (!input_.empty()) {
            const size_t bytes = input_.byte_size();
            auto result = std::move(input_);
            input_.ReleaseIfIdle();
            AcknowledgeInput(bytes);
            co_return result;
        }
        if (cancelled_)
            throw transport::LinkError(ErrorCode::CANCELLED);
        if (input_done_) co_return buf::MultiBuffer{};
        auto [error] = co_await input_signal_.async_receive(
            net::as_tuple(net::use_awaitable));
        if (error == net::experimental::error::channel_cancelled)
            error = net::error::operation_aborted;
        if (error)
            throw IoSystemError(error, "QUIC stream input cancelled");
    }
}

net::awaitable<void> QuicStreamState::WriteMultiBuffer(buf::MultiBuffer payload) {
    CheckWriteOpen();
    auto owner = owner_.lock();
    if (!owner) {
        payload.clear();
        throw transport::LinkError(ErrorCode::CONNECTION_CLOSED);
    }
    co_await owner->WriteStream(stream_id_, std::move(payload));
}

void QuicStreamState::ShutdownWrite() noexcept {
    if (write_done_) return;
    write_done_ = true;
    NotifyWritable();
    if (auto owner = owner_.lock()) owner->ShutdownStreamWrite(stream_id_);
}

void QuicStreamState::CheckWriteOpen() const {
    if (cancelled_) throw transport::LinkError(ErrorCode::CANCELLED);
    if (write_done_) throw transport::WriteClosed();
}

net::awaitable<void> QuicStreamState::WaitWritable() {
    CheckWriteOpen();
    if (!output_wait_)
        output_wait_ = std::make_unique<OutputWait>(io_context_.get_executor());
    struct PendingWriteWait {
        QuicStreamState& owner;
        OutputWait& wait;
        ~PendingWriteWait() {
            if (--wait.waiters == 0) owner.output_wait_.reset();
        }
    } pending{*this, *output_wait_};
    ++pending.wait.waiters;
    const auto cancellation = co_await net::this_coro::cancellation_state;
    auto [error] = co_await pending.wait.ready.async_receive(
        net::as_tuple(net::use_awaitable));
    CheckWriteOpen();
    if (cancellation.cancelled() != net::cancellation_type::none)
        throw IoSystemError(net::error::operation_aborted, "QUIC stream output cancelled");
    // channel.cancel() is the broadcast event, not stream cancellation.
    if (error && error != net::experimental::error::channel_cancelled)
        throw IoSystemError(error, "QUIC stream output cancelled");
}

void QuicStreamState::NotifyWritable() noexcept {
    if (output_wait_) output_wait_->ready.cancel();
}

void QuicStreamState::WakeReader() noexcept {
    (void)input_signal_.try_send(IoErrorCode{});
}

QuicStream::QuicStream(std::shared_ptr<QuicStreamState> state)
    : state_(std::move(state))
    , deadline_(state_->IoContext(), *this) {}

QuicStream::~QuicStream() noexcept {
    Close();
}

net::awaitable<size_t> QuicStream::AsyncRead(net::mutable_buffer buffer) {
    if (closed_) co_return 0;
    co_return co_await state_->Read(buffer);
}

net::awaitable<size_t> QuicStream::AsyncWrite(net::const_buffer buffer) {
    co_await WriteBuffers(std::span(&buffer, 1));
    co_return buffer.size();
}

net::awaitable<buf::MultiBuffer> QuicStream::ReadMultiBuffer() {
    if (closed_) co_return buf::MultiBuffer{};
    co_return co_await state_->ReadMultiBuffer();
}

net::awaitable<void> QuicStream::WriteMultiBuffer(buf::MultiBuffer payload) {
    if (closed_) {
        payload.clear();
        throw transport::LinkError(ErrorCode::CONNECTION_CLOSED);
    }
    co_await state_->WriteMultiBuffer(std::move(payload));
}

net::awaitable<void> QuicStream::WriteBuffers(
    std::span<const net::const_buffer> buffers) {
    if (closed_) throw transport::LinkError(ErrorCode::CONNECTION_CLOSED);
    buf::MultiBuffer payload;
    for (const auto& buffer : buffers) {
        const auto bytes = std::span(
            static_cast<const uint8_t*>(buffer.data()), buffer.size());
        if (!buf::AppendSpanToMultiBuffer(bytes, payload)) throw std::bad_alloc();
    }
    co_await WriteMultiBuffer(std::move(payload));
}

void QuicStream::ShutdownWrite() {
    if (!closed_) state_->ShutdownWrite();
}

void QuicStream::Cancel() noexcept {
    if (!closed_) state_->Cancel();
}

void QuicStream::Close() {
    deadline_.Clear();
    if (std::exchange(closed_, true)) return;
    if (!state_->DuplexFinished()) state_->Cancel();
}

void QuicStream::CloseAbortive() {
    deadline_.Clear();
    if (std::exchange(closed_, true)) return;
    state_->Cancel();
}

bool QuicStream::IsOpen() const {
    return !closed_ && state_->Open();
}

UdpSessionStream::UdpSessionStream(
    net::io_context& io_context, uint32_t session_id,
    TargetAddress first_target, std::weak_ptr<Connection> owner)
    : session_id_(session_id)
    , first_target_(std::move(first_target))
    , owner_(std::move(owner))
    , signal_(io_context.get_executor(), 1)
    , deadline_(io_context, *this) {}

UdpSessionStream::~UdpSessionStream() noexcept {
    Close();
}

bool UdpSessionStream::Push(
    const TargetAddress& target, std::span<const uint8_t> payload) {
    if (closed_ || cancelled_) return false;
    // Datagrams cannot share a block. Count rounded capacity before allocating,
    // without subtracting an externally sized payload from the byte budget.
    const size_t buffer_count = payload.empty()
        ? 1 : 1 + (payload.size() - 1) / buf::Buffer::kSize;
    if (buffer_count > kMaxQueuedBytes / buf::Buffer::kSize - queued_buffer_count_)
        return false;
    buf::MultiBuffer packet;
    if (!buf::AppendSpanToMultiBuffer(payload, packet) ||
        !buf::SetUdpTarget(packet, target)) return false;
    input_.push_back(std::move(packet));
    queued_buffer_count_ += buffer_count;
    WakeReader();
    return true;
}

void UdpSessionStream::Detach() noexcept {
    owner_.reset();
    Close();
}

net::awaitable<size_t> UdpSessionStream::AsyncRead(net::mutable_buffer) {
    throw transport::LinkError(ErrorCode::NOT_SUPPORTED);
}

net::awaitable<size_t> UdpSessionStream::AsyncWrite(net::const_buffer) {
    throw transport::LinkError(ErrorCode::NOT_SUPPORTED);
}

net::awaitable<buf::MultiBuffer> UdpSessionStream::ReadMultiBuffer() {
    for (;;) {
        if (cancelled_) throw transport::LinkError(ErrorCode::CANCELLED);
        if (!input_.empty()) {
            auto packet = std::move(input_.front());
            input_.pop_front();
            queued_buffer_count_ -= packet.size();
            co_return packet;
        }
        if (closed_) co_return buf::MultiBuffer{};
        auto [error] = co_await signal_.async_receive(
            net::as_tuple(net::use_awaitable));
        if (error == net::experimental::error::channel_cancelled)
            error = net::error::operation_aborted;
        if (error)
            throw IoSystemError(error, "Hysteria UDP session input cancelled");
    }
}

net::awaitable<void> UdpSessionStream::WriteMultiBuffer(buf::MultiBuffer packet) {
    const auto datagram = buf::InspectUdpDatagram(packet);
    if (datagram.status == buf::UdpDatagramStatus::Empty) co_return;
    if (!datagram.Valid() || datagram.payload_size > kMaxUdpPayloadLength) {
        packet.clear();
        throw transport::LinkError(ErrorCode::PROTOCOL_INVALID_ADDRESS);
    }
    auto owner = owner_.lock();
    if (closed_ || !owner) {
        packet.clear();
        throw transport::LinkError(ErrorCode::CONNECTION_CLOSED);
    }
    bool sent = false;
    if (datagram.buffer_count == 1) {
        sent = owner->SendUdpMessage(
            session_id_, *datagram.target, datagram.single_buffer->Bytes());
    } else {
        memory::ThreadLocalVector<uint8_t> payload;
        payload.reserve(datagram.payload_size);
        for (const auto* buffer : packet) {
            if (!buffer || buffer->IsEmpty()) continue;
            const auto bytes = buffer->Bytes();
            payload.insert(payload.end(), bytes.begin(), bytes.end());
        }
        sent = owner->SendUdpMessage(session_id_, *datagram.target, payload);
    }
    packet.clear();
    if (!sent) throw transport::LinkError(ErrorCode::RESOURCE_EXHAUSTED);
}

void UdpSessionStream::Cancel() noexcept {
    cancelled_ = true;
    // No later read can consume this input; release it before callbacks can
    // retain or destroy the cancelled host.
    input_.clear();
    queued_buffer_count_ = 0;
    WakeReader();
    NotifyCancellation();
}

void UdpSessionStream::Close() {
    deadline_.Clear();
    if (closed_) return;
    closed_ = true;
    input_.clear();
    queued_buffer_count_ = 0;
    WakeReader();
    if (auto owner = std::exchange(owner_, {}).lock())
        owner->CloseUdpSession(session_id_);
    NotifyClosed();
}

void UdpSessionStream::WakeReader() noexcept {
    (void)signal_.try_send(IoErrorCode{});
}

}  // namespace transport::internet::hysteria
