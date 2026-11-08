#include "hysteria_ingress.hpp"

#include "quic_connection.hpp"
#include "hysteria_protocol.hpp"
#include "hysteria_settings.hpp"
#include "quic_memory.hpp"
#include "quic_stream.hpp"

#include "app/proxyman/inbound/handler.hpp"
#include "app/proxyman/inbound/receiver_settings.hpp"
#include "app/proxyman/inbound/user_store.hpp"
#include "app/rate_limiter.hpp"
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
#include "../tls_client_context.hpp"
#include "../../../proxy/inbound_admission.hpp"
#include "../../../common/awaitable_task_group.hpp"

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
#include <limits>
#include <optional>
#include <stdexcept>
#include <utility>

namespace transport::internet::hysteria {

struct SslContextDeleter {
    void operator()(SSL_CTX* context) const noexcept { SSL_CTX_free(context); }
};
using SslContextPtr = std::unique_ptr<SSL_CTX, SslContextDeleter>;

namespace {

constexpr size_t kServerConnectionIdLength = 18;
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

struct PendingPacket {
    std::shared_ptr<SocketState> socket;
    udp::endpoint remote;
    ConnectionId cid;
    memory::ThreadLocalVector<uint8_t> bytes;
};

struct SocketState final : memory::ThreadAllocated {
    explicit SocketState(net::io_context& io)
        : changed(io, 1)
        , drained(io, std::chrono::steady_clock::time_point::max()) {}
    HysteriaIngress::SocketPtr socket;
    memory::ThreadLocalString key;
    udp::endpoint local;
    udp::endpoint remote;
    struct Output {
        memory::ByteVector data;
        udp::endpoint remote;
        std::shared_ptr<QuicOwnership> owner;
        bool terminal = false;
    };
    memory::ThreadLocalDeque<Output> output;
    SignalChannel changed;
    std::shared_ptr<QuicOwnership> sending;
    net::steady_timer drained;
};

// Worker-local sockets, receive staging, native send ownership and one expiry
// timer. Connection business tasks live in their own migratable domains.
class QuicListener final : public memory::ThreadAllocated {
public:
    QuicListener(uint32_t worker_id, net::io_context& io,
                 app::DatagramSessionEnvironment environment);

    [[nodiscard]] const proxyman::inbound::ReceiverSettings& Receiver() const noexcept {
        return *environment.receiver;
    }

    void Spawn(net::awaitable<void> task);
    [[nodiscard]] bool Queue(SocketState& socket, std::span<const uint8_t> data,
                             udp::endpoint remote,
                             std::shared_ptr<QuicOwnership> owner, bool terminal = false);
    void Associate(const ngtcp2_cid& cid, std::shared_ptr<Connection> connection);
    void PublishIds(const std::shared_ptr<Connection>& connection);
    net::awaitable<void> Publish(std::shared_ptr<QuicOwnership> owner);
    void Dissociate(const ngtcp2_cid& cid) noexcept;
    void DissociateAll(const std::shared_ptr<QuicOwnership>& owner) noexcept;
    SocketState* Resolve(const udp::endpoint& local) noexcept;
    net::awaitable<void> Drain(const std::shared_ptr<QuicOwnership>& owner);
    void Enqueue(std::shared_ptr<Connection> connection, PendingPacket packet);
    void Pump(const std::shared_ptr<Connection>& connection);
    net::awaitable<void> Claim(std::shared_ptr<QuicOwnership> owner);
    struct ClaimWait final : TimeoutEvent {
        explicit ClaimWait(net::io_context& io)
            : TimeoutEvent(WorkerLocal{}), wake(io, 1) {}
        void Notify() { (void)wake.try_send(IoErrorCode{}); }
        void OnTimeout() override { Notify(); }
        SignalChannel wake;
    };
    struct Inbox {
        memory::ThreadLocalDeque<PendingPacket> packets;
        size_t bytes = 0;
        bool scheduled = false;
        std::unique_ptr<ClaimWait> claim;
    };
    bool Stage(Inbox& inbox, PendingPacket packet);
    memory::ThreadLocalUnorderedMap<QuicOwnership*, std::shared_ptr<Inbox>> inboxes;
    app::DatagramSessionEnvironment environment;
    QuicDirectory& directory;
    std::string directory_space;
    std::shared_ptr<QuicListenerIdentity> identity = std::make_shared<QuicListenerIdentity>();
    size_t connection_tasks = 0;
    size_t pending_claims = 0;
    memory::ThreadLocalUnorderedMap<QuicOwnership*, std::shared_ptr<Connection>> sessions;
    net::awaitable<void> ReceiveLoop(std::shared_ptr<SocketState> socket);
    net::awaitable<void> SendLoop(std::shared_ptr<SocketState> socket);
    void ArmExpiry();
    net::awaitable<void> ExpiryLoop();
    void Stop() noexcept;

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

Connection::Connection(
    QuicListener& listener, SocketState& socket, const udp::endpoint& remote)
    : listener_(&listener)
    , capabilities_(app::PhysicalSessionCapabilities::Create(
          listener.environment.configuration, listener.environment.limiter,
          listener.environment.request_load, *listener.environment.dns_worker,
          listener.environment.prepared, listener.environment.receiver))
    , ownership_([&] {
          auto owner = std::make_shared<QuicOwnership>();
          owner->domain = ExecutionDomain::Create(listener.io, listener.worker_id,
              listener.io.get_executor(), capabilities_, listener.environment.coordinator);
          owner->owner.store(listener.worker_id);
          owner->listener.store(listener.identity.get());
          return owner;
      }())
    , closed_signal_(ownership_->domain->Executor(), 1)
    , physical_ready_(ownership_->domain->Executor(), 1) {
    capabilities_->BindDomain(ownership_->domain);
    retirement_ = std::make_unique<QuicDirectory::Retirement>(
        listener.directory, listener.directory_space, ownership_);
    memory::ScopedAllocationDomain scope(capabilities_->Allocation());
    core_ = std::make_unique<Core>(capabilities_->Allocation());
    core_->local = socket.local;
    core_->remote = remote;
    InitializeBaseContext(remote);
}

std::shared_ptr<Connection> Connection::Create(
    QuicListener& listener, SocketState& socket,
    const udp::endpoint& remote, const ngtcp2_pkt_hd& header) {
    auto connection = std::shared_ptr<Connection>(
        new Connection(listener, socket, remote));
    connection->ownership_->connection = connection;
    connection->registry_ = listener.environment.registry;
    bool tracked = false;
    try {
        {
            memory::ScopedWorkerAllocation worker_allocation;
            listener.Associate(header.dcid, connection);
            listener.sessions.emplace(connection->ownership_.get(), connection);
            ++listener.connection_tasks;
            tracked = true;
        }
        net::co_spawn(connection->Executor(), connection->Run(header),
            [connection](std::exception_ptr error) {
                auto* owner = connection->listener_;
                connection->Close();
                memory::ScopedWorkerAllocation worker_allocation;
                owner->sessions.erase(connection->ownership_.get());
                MaybeShrinkHashContainer(owner->sessions);
                owner->inboxes.erase(connection->ownership_.get());
                MaybeShrinkHashContainer(owner->inboxes, 8);
                --owner->connection_tasks;
                owner->changed.cancel();
                if (error && !IsOperationCancelled(error))
                    LOG_ERROR("Hysteria connection task failed worker={}", owner->worker_id);
            });
    } catch (...) {
        {
            memory::ScopedAllocationDomain scope(connection->capabilities_->Allocation());
            connection->Close();
        }
        memory::ScopedWorkerAllocation worker_allocation;
        listener.sessions.erase(connection->ownership_.get());
        MaybeShrinkHashContainer(listener.sessions);
        if (tracked) --listener.connection_tasks;
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
    cid->datalen = length;
    if (RAND_bytes(token, NGTCP2_STATELESS_RESET_TOKENLEN) != 1)
        return NGTCP2_ERR_CALLBACK_FAILURE;
    auto* target = self.validating_ ? self.validation_listener_ : self.listener_;
    try { target->Associate(*cid, self.shared_from_this()); }
    catch (...) { return NGTCP2_ERR_CALLBACK_FAILURE; }
    return 0;
}

int Connection::RemoveConnectionId(ngtcp2_conn*, const ngtcp2_cid* cid,
    void* user_data) {
    auto& self = *static_cast<Connection*>(user_data);
    auto* target = self.validating_ ? self.validation_listener_ : self.listener_;
    target->Dissociate(*cid);
    std::erase(self.connection_ids_, ConnectionId(*cid));
    try { target->PublishIds(self.shared_from_this()); }
    catch (...) { return NGTCP2_ERR_CALLBACK_FAILURE; }
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

    const auto& timeouts = listener_->environment.configuration->timeouts;
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
            core_->memory.Ngtcp2(), this) != 0)
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

net::awaitable<void> Connection::Run(ngtcp2_pkt_hd header) {
    std::exception_ptr failure;
    try {
        registry_record_ = registry_->Register(capabilities_, ownership_->domain);
        registry_record_->conn_id = base_context_.conn_id;
        co_await RunAwaitableTaskGroup(Executor(), [&](AwaitableTaskGroup& tasks) {
            tasks_ = &tasks;
            capabilities_->Initialize(Reactor(), tasks);
            registry_record_->initialized.store(true, std::memory_order_release);
            ownership_->domain->RegisterResource(*this);
            resource_registered_ = true;
            if (!Initialize(header)) {
                Close();
                return;
            }
            listener_->Associate(core_->server_cid, shared_from_this());
            capabilities_->Stats().OnConnectionAccepted();
            stats_open_ = true;
            tasks.Spawn(WaitClosed());
            tasks.Spawn(ReservePhysicalAdmission());
            listener_->Pump(shared_from_this());
        });
    } catch (...) { failure = std::current_exception(); }
    Close();
    tasks_ = nullptr;
    co_await listener_->Drain(ownership_);
    if (resource_registered_) {
        ownership_->domain->UnregisterResource(*this);
        resource_registered_ = false;
    }
    core_.reset();
    try { co_await capabilities_->AsyncJoin(); }
    catch (...) { if (!failure) failure = std::current_exception(); }
    if (registry_record_) co_await registry_->Retire(std::move(registry_record_));
    if (failure) std::rethrow_exception(failure);
}

net::awaitable<void> Connection::WaitClosed() {
    if (!closed_) {
        auto [error] = co_await closed_signal_.async_receive(
            net::as_tuple(net::use_awaitable));
        (void)error;
    }
    Close();
    capabilities_->RequestStop();
}

SocketState* Connection::OutputSocket(const ngtcp2_path& path) const noexcept {
    if (path.user_data != &core_->path_binding) return nullptr;
    auto local = EndpointFromAddress(path.local);
    return local ? (validating_ ? validation_listener_ : listener_)->Resolve(*local) : nullptr;
}

void Connection::PublishExpiry() noexcept {
    ownership_->expiry.store(Expiry());
    (validating_ ? validation_listener_ : listener_)->ArmExpiry();
}

net::awaitable<void> Connection::PrepareHandoff(const ExecutionDomain::HandoffTarget&) {
    // Runs on the old native Worker after all business callbacks have exited.
    {
        memory::ScopedWorkerAllocation worker_allocation;
        listener_->DissociateAll(ownership_);
        listener_->inboxes.erase(ownership_.get());
        MaybeShrinkHashContainer(listener_->inboxes, 8);
    }
    co_await listener_->Drain(ownership_);
    listener_->ArmExpiry();
}

void Connection::CommitHandoff(const ExecutionDomain::HandoffTarget& target) noexcept {
    auto* previous = listener_;
    const auto previous_worker = previous->worker_id;
    listener_ = validation_listener_;
    ++listener_->connection_tasks;
    ownership_->owner.store(target.worker_id);
    ownership_->listener.store(listener_->identity.get());
    net::post(previous->io, [previous, owner = ownership_] {
        memory::ScopedWorkerAllocation worker_allocation;
        if (owner->listener.load() != previous->identity.get()) {
            previous->sessions.erase(owner.get());
            MaybeShrinkHashContainer(previous->sessions);
        }
        --previous->connection_tasks;
        previous->changed.cancel();
    });
    base_context_.worker_id = target.worker_id;
    core_->local = candidate_local_;
    core_->remote = candidate_remote_;
    EndValidation(true);
    try {
        LOG_CONN_DEBUG(base_context_, "QUIC passive handoff committed old_owner={} receiving_worker={} remote={}:{} path_evidence={}",
            previous_worker, target.worker_id, iputil::AddressText(candidate_remote_.address()).View(),
            candidate_remote_.port(), validation_reused_ ? "reused" : "challenge");
    } catch (...) {} // A logging allocation must not interrupt native commit.
}

net::awaitable<void> Connection::CancelHandoff(const ExecutionDomain::HandoffTarget&) {
    // Server-side ngtcp2 has no public rollback API. A rejected ciphertext
    // leaves the path untouched, and a failed probe normally restores its
    // fallback. Never resume an old owner with a different selected path.
    const bool path_changed = validating_ && !closed_ &&
        !ngtcp2_path_eq(ngtcp2_conn_get_path(core_->quic),
                        &validation_original_path_.path);
    // Claim has already removed target-local CIDs and drained its publication
    // and socket work. From here onward only the original Worker is accessible.
    EndValidation(false);
    if (path_changed) {
        Close();
        LOG_DEBUG("QUIC passive rollback closed connection worker={} reason=selected-path-changed",
            listener_->worker_id);
    }
    if (!closed_) {
        memory::ScopedWorkerAllocation worker_allocation;
        for (const auto& cid : connection_ids_)
            listener_->connections.emplace(cid, shared_from_this());
        PublishExpiry();
    }
    co_return;
}

void Connection::BeginValidation(QuicListener& target, const udp::endpoint& local,
                                 const udp::endpoint& remote) {
    validation_listener_ = &target;
    candidate_local_ = local;
    candidate_remote_ = remote;
    validating_ = true;
    validation_succeeded_ = false;
    validation_reused_ = false;
    validation_authenticated_ = false;
    validation_pending_ = false;
    ngtcp2_path_storage_zero(&validation_original_path_);
    ngtcp2_path_copy(&validation_original_path_.path, ngtcp2_conn_get_path(core_->quic));
}

bool Connection::CandidateSelected() const noexcept {
    const auto* path = ngtcp2_conn_get_path(core_->quic);
    auto local = EndpointFromAddress(path->local);
    auto remote = EndpointFromAddress(path->remote);
    return local && remote && *local == candidate_local_ && *remote == candidate_remote_;
}

int Connection::PathValidationStarted(ngtcp2_conn*, uint32_t,
    const ngtcp2_path* path, const ngtcp2_path*, void* user_data) {
    auto& self = *static_cast<Connection*>(user_data);
    if (!self.validating_) return 0;
    auto local = EndpointFromAddress(path->local);
    auto remote = EndpointFromAddress(path->remote);
    // Only a probe started for this claim is evidence. ngtcp2's background
    // fallback probes can finish silently, without a path_validation callback.
    if (local && remote && *local == self.candidate_local_ &&
        *remote == self.candidate_remote_) self.validation_pending_ = true;
    return 0;
}

int Connection::PathValidated(ngtcp2_conn*, uint32_t,
    const ngtcp2_path* path, const ngtcp2_path*,
    ngtcp2_path_validation_result result, void* user_data) {
    auto& self = *static_cast<Connection*>(user_data);
    if (!self.validating_) return 0;
    auto local = EndpointFromAddress(path->local);
    auto remote = EndpointFromAddress(path->remote);
    if (local && remote && *local == self.candidate_local_ &&
        *remote == self.candidate_remote_) {
        self.validation_pending_ = false;
        if (result == NGTCP2_PATH_VALIDATION_RESULT_SUCCESS)
            self.validation_succeeded_ = true;
    }
    return 0;
}

void Connection::EndValidation(bool committed) noexcept {
    validating_ = false;
    if (!committed) validation_listener_ = nullptr;
}

bool Connection::Feed(SocketState& socket, const udp::endpoint& remote,
                      std::span<const uint8_t> packet) {
    if (!core_ || closed_) return false;
    auto local_addr = MakeAddress(socket.local);
    auto remote_addr = MakeAddress(remote);
    ngtcp2_path path{local_addr, remote_addr, &core_->path_binding};
    ngtcp2_pkt_info packet_info{};
    const bool candidate_was_selected = validating_ && CandidateSelected();
    uint64_t packets_received = 0;
    if (validating_) {
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
            capabilities_->Stats().OnError();
        Close();
        return false;
    }
    if (validating_) {
        ngtcp2_conn_info info{};
        ngtcp2_conn_get_conn_info(core_->quic, &info);
        // pkt_recv excludes AEAD failures and replay-discarded packets.
        // read_pkt returning zero alone is not evidence of accepted input.
        if (info.pkt_recv == packets_received) return !closed_;
        if (!packet.empty() && !(packet.front() & 0x80))
            validation_authenticated_ = true;
    }
    if (validating_ && validation_authenticated_ && !candidate_was_selected &&
        CandidateSelected() && !CandidateValidationPending() && !validation_succeeded_) {
        // ngtcp2 selects a different server path only after authenticated,
        // fresh non-probing 1-RTT input (or a verified PATH_RESPONSE). When
        // no validation is pending and no SUCCESS fired, it reused a
        // validated history/fallback path. Merely decrypting a replay or
        // returning zero from read_pkt cannot satisfy this transition.
        validation_succeeded_ = true;
        validation_reused_ = true;
    }
    Flush();
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
                if (bytes != 0) it->second.output.push_back(std::move(payload));
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
        if (!validating_ && core_->http) {
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
        if (!validating_ && !http_data && !core_->streams.empty()) {
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
        ngtcp2_path path{local, remote, &core_->path_binding};
        ngtcp2_pkt_info packet_info{};
        if (!validating_ && !core_->datagrams.empty()) {
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
            auto* output_socket = OutputSocket(path);
            auto output_remote = EndpointFromAddress(path.remote);
            if (!output_socket || !output_remote ||
                !listener_->Queue(*output_socket,
                    std::span<const uint8_t>(packet.data(), static_cast<size_t>(written)),
                    *output_remote, ownership_)) {
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
            core_->quic, &path, &packet_info, packet.data(), packet.size(),
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
        auto* output_socket = OutputSocket(path);
        auto output_remote = EndpointFromAddress(path.remote);
        auto* sender = validating_ ? validation_listener_ : listener_;
        if (!output_socket || !output_remote ||
            !sender->Queue(*output_socket,
                std::span<const uint8_t>(packet.data(), static_cast<size_t>(written)),
                *output_remote, ownership_)) {
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
        ownership_->retired.store(true);
        if (retirement_) ownership_->domain->Coordinator().PostReserved(std::move(retirement_));
        (validating_ ? validation_listener_ : listener_)->DissociateAll(ownership_);
    }
    if (physical_ == PhysicalAdmission::Pending) (void)physical_ready_.try_send(IoErrorCode{});
    if (stats_open_) {
        capabilities_->Stats().OnConnectionClosed();
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
        capabilities_->Stats().OnError();
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
                        core_->remote, ownership_, true);
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
    auto* limiter = listener_->environment.limiter.get();
    while (physical_ == PhysicalAdmission::Pending && !closed_) {
        auto [error] = co_await physical_ready_.async_receive(
            net::as_tuple(net::use_awaitable));
        if (error) co_return AdmitResult::Limited;
    }
    if (closed_ || physical_ != PhysicalAdmission::Admitted)
        co_return AdmitResult::Limited;
    const auto credential_revision = proxyman::inbound::UserStore::CredentialRevision(
        proxyman::inbound::UserProtocol::Hysteria, base_context_.inbound.tag);
    const auto failure_key = limiter
        ? std::optional(limiter->FingerprintCredential(
              base_context_.inbound.tag, auth_hash, credential_revision))
        : std::nullopt;
    if (failure_key) {
        const auto error = co_await proxy::CheckInboundCredential(
            *limiter, base_context_, *failure_key,
            proxyman::inbound::UserProtocol::Hysteria, credential_revision);
        if (error != ErrorCode::OK) {
            capabilities_->Stats().OnError();
            co_return AdmitResult::Limited;
        }
    }
    if (closed_) co_return AdmitResult::Limited;
    const auto& receiver = listener_->Receiver();
    auto user = proxyman::inbound::UserStore::FindHysteriaUser(
        receiver.inbound_tag, auth_hash);
    if (!user) {
        co_await proxy::RecordInboundAuthFailure(
            limiter, base_context_, "no matching credential", failure_key);
        capabilities_->Stats().OnError();
        co_return AdmitResult::AuthFailed;
    }
    const auto profile = user->profile;
    user.reset();
    proxy::BindAuthenticatedInbound(base_context_, profile, std::nullopt);
    auto session = co_await proxy::AdmitAuthenticatedInbound(
        capabilities_->Tracker(), listener_->environment.limiter->Coordinator(), base_context_, profile);
    if (!session) co_return AdmitResult::DeviceLimited;
    if (closed_) co_return AdmitResult::Limited;
    online_session_.emplace(std::move(*session));
    stream_sink_ = capabilities_->MakeAuthenticatedStreamSink(base_context_,
        physical_reservation_.FamilyLease());
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
        if (input.empty()) return;
        std::array<uint8_t, 1> kind{};
        (void)input.CopyPrefixTo(kind);
        if (kind[0] != 0) {
            memory::ThreadLocalVector<uint8_t> header(
                std::min(input.byte_size(), kMaxStreamHeaderBytes));
            (void)input.CopyPrefixTo(header);
            auto request = ParseV1Request(header);
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

QuicListener::QuicListener(
    uint32_t worker_id_value, net::io_context& io_value,
    app::DatagramSessionEnvironment environment_value)
    : environment(std::move(environment_value)),
      directory(net::use_service<QuicDirectory>(environment.coordinator->Services())),
      directory_space(std::string(environment.receiver->inbound_tag) + ":" +
          std::to_string(reinterpret_cast<uintptr_t>(environment.prepared->settings.get()))),
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

void QuicListener::Spawn(net::awaitable<void> task) {
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

bool QuicListener::Queue(SocketState& socket, std::span<const uint8_t> data,
                         udp::endpoint remote, std::shared_ptr<QuicOwnership> owner,
                         bool terminal) {
    memory::ScopedWorkerAllocation worker_allocation;
    if (stopping || socket.output.size() >= kMaxQueuedSocketPackets) return false;
    socket.output.push_back({
        memory::ByteVector(data.begin(), data.end()),
        std::move(remote), std::move(owner), terminal});
    (void)socket.changed.try_send(IoErrorCode{});
    return true;
}

void QuicListener::Associate(
    const ngtcp2_cid& cid, std::shared_ptr<Connection> connection) {
    memory::ScopedWorkerAllocation worker_allocation;
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
    PublishIds(connection);
}

void QuicListener::PublishIds(const std::shared_ptr<Connection>& connection) {
    memory::ScopedWorkerAllocation worker_allocation;
    auto owner = connection->Ownership();
    owner->published_ids.assign(
        connection->connection_ids_.begin(), connection->connection_ids_.end());
    owner->publication_pending = true;
    if (owner->publishing || owner->retired.load()) return;
    owner->publishing = true;
    try { Spawn(Publish(std::move(owner))); }
    catch (...) { owner->publishing = false; throw; }
}

net::awaitable<void> QuicListener::Publish(std::shared_ptr<QuicOwnership> owner) {
    co_await net::this_coro::reset_cancellation_state(net::disable_cancellation());
    try {
        while (owner->publication_pending && !owner->retired.load()) {
            owner->publication_pending = false;
            auto ids = owner->published_ids;
            const bool published = co_await environment.coordinator->PostCall(
                [index = &directory, space = directory_space, owner, ids = std::move(ids)]() mutable {
                    return index->Publish(space, std::move(ids), owner);
                });
            if (!published && !owner->retired.load())
                throw std::runtime_error("QUIC CID publication collision");
        }
    } catch (const std::exception& error) {
        owner->retired.store(true);
        DissociateAll(owner);
        owner->domain->Execute([weak = owner->connection] {
            if (auto c = weak.lock()) c->Close();
        });
        try { LOG_DEBUG("QUIC CID publication failed worker={} reason={}", worker_id, error.what()); }
        catch (...) {} // Diagnostic allocation cannot strand the publication gate.
    } catch (...) {
        owner->retired.store(true);
        DissociateAll(owner);
        owner->domain->Execute([weak = owner->connection] {
            if (auto c = weak.lock()) c->Close();
        });
        try { LOG_ERROR("QUIC CID publication failed worker={}", worker_id); }
        catch (...) {} // Closing and waking the native drain remain mandatory.
    }
    owner->publishing = false;
    for (auto& [key, socket] : sockets) {
        (void)key;
        (void)socket->changed.try_send(IoErrorCode{});
    }
    changed.cancel();
}

void QuicListener::Dissociate(const ngtcp2_cid& cid) noexcept {
    memory::ScopedWorkerAllocation worker_allocation;
    connections.erase(ConnectionId(cid));
    MaybeShrinkHashContainer(connections);
}

void QuicListener::DissociateAll(const std::shared_ptr<QuicOwnership>& owner) noexcept {
    memory::ScopedWorkerAllocation worker_allocation;
    std::erase_if(connections, [&](const auto& entry) {
        return entry.second->Ownership() == owner;
    });
    MaybeShrinkHashContainer(connections);
}

SocketState* QuicListener::Resolve(const udp::endpoint& local) noexcept {
    for (auto& [key, socket] : sockets) {
        (void)key;
        if (socket->local == local && socket->socket && socket->socket->is_open())
            return socket.get();
    }
    return nullptr;
}

net::awaitable<void> QuicListener::Drain(const std::shared_ptr<QuicOwnership>& owner) {
    while (owner->publishing) {
        auto [error] = co_await changed.async_wait(net::as_tuple(net::use_awaitable));
        (void)error;
    }
    for (auto& [key, socket] : sockets) {
        (void)key;
        size_t kept = 0;
        for (size_t index = 0; index < socket->output.size(); ++index) {
            if (socket->output[index].owner == owner) {
                if (!socket->output[index].terminal) continue;
                socket->output[index].owner.reset();
            }
            if (kept != index)
                socket->output[kept] = std::move(socket->output[index]);
            ++kept;
        }
        while (socket->output.size() > kept) socket->output.pop_back();
        while (socket->sending == owner) {
            auto [error] = co_await socket->drained.async_wait(net::as_tuple(net::use_awaitable));
            (void)error;
        }
    }
}

bool QuicListener::Stage(Inbox& inbox, PendingPacket packet) {
    if (inbox.packets.size() >= 64 || packet.bytes.size() > 256 * 1024 - inbox.bytes)
        return false;
    const size_t bytes = packet.bytes.size();
    inbox.packets.push_back(std::move(packet));
    inbox.bytes += bytes;
    if (inbox.claim) inbox.claim->Notify();
    return true;
}

void QuicListener::Enqueue(std::shared_ptr<Connection> connection, PendingPacket packet) {
    memory::ScopedWorkerAllocation worker_allocation;
    auto owner = connection->Ownership();
    if (owner->retired.load() || owner->claiming.load() || owner->owner.load() != worker_id) return;
    auto& slot = inboxes[owner.get()];
    if (!slot) slot = memory::AllocateShared<Inbox>();
    if (!Stage(*slot, std::move(packet)) || slot->scheduled) return;
    slot->scheduled = true;
    // Only metadata enters the migratable queue. A stale operation cannot
    // access its old listener, nor carry a packet to the new Worker.
    owner->domain->Execute([this, connection, owner, binding = identity] {
        if (owner->listener.load() != binding.get() ||
            owner->claiming.load() || owner->retired.load()) return;
        Pump(connection);
    });
}

void QuicListener::Pump(const std::shared_ptr<Connection>& connection) {
    if (!connection->core_->quic || !connection->tasks_) return;
    const auto& owner = connection->Ownership();
    if (owner->claiming.load() || owner->retired.load()) return;
    auto found = inboxes.find(owner.get());
    if (found == inboxes.end()) return;
    auto inbox = found->second;
    inbox->scheduled = false;
    while (!inbox->packets.empty() && !connection->Closed()) {
        auto packet = std::move(inbox->packets.front());
        inbox->packets.pop_front();
        inbox->bytes -= packet.bytes.size();
        connection->Feed(*packet.socket, packet.remote, packet.bytes);
    }
    if (connection->Closed() || inbox->packets.empty()) {
        memory::ScopedWorkerAllocation worker_allocation;
        inboxes.erase(owner.get());
        MaybeShrinkHashContainer(inboxes, 8);
    }
}

net::awaitable<void> QuicListener::Claim(std::shared_ptr<QuicOwnership> owner) {
    co_await net::this_coro::reset_cancellation_state(net::disable_cancellation());
    auto connection = owner->connection.lock();
    auto inbox = inboxes.at(owner.get());
    std::shared_ptr<ExecutionDomain::Handoff> ticket;
    bool committed = false;
    try {
        if (!connection || stopping || owner->retired.load()) throw std::runtime_error("retired QUIC claim");
        ticket = co_await owner->domain->PreparePassiveHandoff(
            {worker_id, &io, io.get_executor()});
        bool eligible = false;
        co_await ticket->Validate([&] {
            if (!connection->Authenticated() || connection->Closed() || inbox->packets.empty()) return;
            const auto* current = ngtcp2_conn_get_path(connection->core_->quic);
            auto remote = EndpointFromAddress(current->remote);
            auto local = EndpointFromAddress(current->local);
            const auto& first = inbox->packets.front();
            if (std::find(connection->connection_ids_.begin(), connection->connection_ids_.end(), first.cid) ==
                connection->connection_ids_.end()) return;
            if (!local || !remote || *local != first.socket->local || *remote == first.remote) return;
            connection->BeginValidation(*this, first.socket->local, first.remote);
            eligible = true;
        });
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
        while (eligible && !stopping && std::chrono::steady_clock::now() < deadline) {
            bool done = false;
            co_await ticket->Validate([&] {
                while (!inbox->packets.empty() && !connection->Closed()) {
                    auto packet = std::move(inbox->packets.front());
                    inbox->packets.pop_front();
                    inbox->bytes -= packet.bytes.size();
                    if (std::find(connection->connection_ids_.begin(), connection->connection_ids_.end(), packet.cid) ==
                        connection->connection_ids_.end()) continue;
                    if (packet.socket->local != connection->candidate_local_ ||
                        packet.remote != connection->candidate_remote_) continue;
                    connection->Feed(*packet.socket, packet.remote, packet.bytes);
                    if (connection->ValidationSucceeded()) break;
                }
                const bool pending = connection->validation_authenticated_ &&
                    connection->CandidateValidationPending();
                if (pending && !connection->Closed() && connection->Expiry() <= Timestamp())
                    connection->OnExpiry();
                done = connection->Closed() || connection->ValidationSucceeded() ||
                    !connection->validation_authenticated_ ||
                    !connection->CandidateValidationPending();
                if (done && !connection->Closed() && !connection->ValidationSucceeded())
                    LOG_DEBUG("QUIC passive claim rejected receiving_worker={} remote={}:{} reason=no-path-evidence",
                        worker_id, iputil::AddressText(connection->candidate_remote_.address()).View(),
                        connection->candidate_remote_.port());
            });
            if (done) break;
            const auto wake_at = std::min(deadline, std::chrono::steady_clock::time_point(
                std::chrono::nanoseconds(owner->expiry.load())));
            if (!inbox->packets.empty()) continue;
            const auto delay = std::chrono::ceil<std::chrono::milliseconds>(
                wake_at - std::chrono::steady_clock::now());
            if (!inbox->claim->ScheduleAfter(delay, io))
                throw std::runtime_error("QUIC claim scheduler stopped");
            auto [error] = co_await inbox->claim->wake.async_receive(net::as_tuple(net::use_awaitable));
            inbox->claim->Cancel();
            (void)error;
        }
        bool valid = false;
        co_await ticket->Validate([&] {
            if (eligible && stopping && connection->validation_authenticated_)
                LOG_DEBUG("QUIC passive claim abandoned receiving_worker={} reason=listener-stopped", worker_id);
            valid = eligible && !stopping && !connection->Closed() && connection->ValidationSucceeded();
            if (!valid) return;
            const auto* selected = ngtcp2_conn_get_path(connection->core_->quic);
            auto local = EndpointFromAddress(selected->local);
            auto remote = EndpointFromAddress(selected->remote);
            valid = local && remote && *local == connection->candidate_local_ &&
                *remote == connection->candidate_remote_;
            if (!valid) return;
            memory::ScopedWorkerAllocation worker_allocation;
            for (const auto& cid : connection->connection_ids_) connections.emplace(cid, connection);
            sessions.emplace(owner.get(), connection);
        });
        if (valid) {
            co_await ticket->Commit();
            committed = true;
        }
    } catch (const std::exception& error) {
        LOG_DEBUG("QUIC passive claim cancelled receiving_worker={} reason={}", worker_id, error.what());
    } catch (...) {
        LOG_DEBUG("QUIC passive claim cancelled receiving_worker={}", worker_id);
    }
    if (!committed) {
        DissociateAll(owner);
        sessions.erase(owner.get());
        MaybeShrinkHashContainer(sessions);
        co_await Drain(owner);
        if (ticket) {
            try { co_await ticket->Cancel(); }
            catch (const std::exception& error) {
                LOG_DEBUG("QUIC passive rollback terminated connection receiving_worker={} reason={}",
                    worker_id, error.what());
            }
            catch (...) {
                LOG_ERROR("QUIC passive rollback terminated connection receiving_worker={} reason=unknown-failure",
                    worker_id);
            }
        }
    }
    owner->claiming.store(false);
    inboxes.erase(owner.get());
    MaybeShrinkHashContainer(inboxes, 8);
    --pending_claims;
    if (connection && !owner->retired.load())
        owner->domain->Execute([connection] { connection->PublishExpiry(); });
    if (committed) {
        while (!inbox->packets.empty()) {
            auto packet = std::move(inbox->packets.front());
            inbox->packets.pop_front();
            Enqueue(connection, std::move(packet));
        }
        ArmExpiry();
    }
}

net::awaitable<void> QuicListener::ReceiveLoop(std::shared_ptr<SocketState> socket) {
    while (!stopping && socket->socket && socket->socket->is_open()) {
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
            memory::ThreadLocalVector<uint8_t> payload(available);
            const size_t bytes = socket->socket->receive_from(
                net::buffer(payload), socket->remote, MSG_TRUNC, error);
            if (error == net::error::operation_aborted) co_return;
            if (error || bytes == 0 || bytes > payload.size()) continue;
            payload.resize(bytes);
            ngtcp2_version_cid version_cid{};
            if (ngtcp2_pkt_decode_version_cid(
                    &version_cid, payload.data(), bytes,
                    kServerConnectionIdLength) != 0)
                continue;
            if (version_cid.dcidlen > NGTCP2_MAX_CIDLEN) continue;
            const ConnectionId cid(version_cid.dcid, version_cid.dcidlen);
            auto found = connections.find(cid);
            std::shared_ptr<Connection> connection =
                found == connections.end() ? nullptr : found->second;
            PendingPacket received{socket, socket->remote, cid, std::move(payload)};
            auto owner = connection ? connection->Ownership() : nullptr;
            if (!owner) {
                try {
                    owner = co_await environment.coordinator->PostCall(
                        [index = &directory, space = directory_space, cid] {
                            return index->Find(space, cid);
                        });
                } catch (const WorkerMailboxFull&) {
                    continue;
                } catch (const std::system_error& failure) {
                    if (failure.code() == net::error::operation_aborted) co_return;
                    throw;
                }
                if (stopping) co_return;
                // Publication or a completed claim may have installed this CID
                // while the metadata-only lookup was suspended.
                found = connections.find(cid);
                if (found != connections.end()) {
                    connection = found->second;
                    owner = connection->Ownership();
                }
            }
            if (owner && !owner->retired.load() && owner->owner.load() != worker_id) {
                auto pending = inboxes.find(owner.get());
                if (pending != inboxes.end()) {
                    Stage(*pending->second, std::move(received));
                    continue;
                }
                if (pending_claims >= 32) continue;
                bool expected = false;
                if (!owner->claiming.compare_exchange_strong(expected, true)) continue;
                ++pending_claims;
                try {
                    auto inbox = memory::AllocateShared<Inbox>();
                    inbox->claim = std::make_unique<ClaimWait>(io);
                    Stage(*inbox, std::move(received));
                    inboxes.emplace(owner.get(), std::move(inbox));
                    Spawn(Claim(owner));
                } catch (...) {
                    --pending_claims;
                    inboxes.erase(owner.get());
                    owner->claiming.store(false);
                    throw;
                }
                continue;
            }
            if (!connection) {
                if (owner || (received.bytes[0] & 0x80) == 0) continue;
                if (connections.size() >= kMaxConnections) {
                    LOG_DEBUG("Hysteria listener connection capacity reached worker={}", worker_id);
                    continue;
                }
                ngtcp2_pkt_hd header{};
                if (ngtcp2_accept(&header, received.bytes.data(), received.bytes.size()) != 0) continue;
                connection = Connection::Create(*this, *socket, received.remote, header);
            }
            Enqueue(std::move(connection), std::move(received));
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

net::awaitable<void> QuicListener::SendLoop(std::shared_ptr<SocketState> socket) {
    while (!stopping && socket->socket && socket->socket->is_open()) {
        if (socket->output.empty()) {
            auto [error] = co_await socket->changed.async_receive(
                net::as_tuple(net::use_awaitable));
            if (error && stopping) co_return;
            continue;
        }
        auto packet = std::move(socket->output.front());
        socket->output.pop_front();
        if (packet.owner->retired.load() && !packet.terminal) continue;
        socket->sending = packet.owner;
        // A CID may not reach the peer until its control-index reservation has
        // succeeded. This gate is local; publication never carries packet bytes.
        while (packet.owner->publishing && !stopping && !packet.terminal) {
            auto [wait_error] = co_await socket->changed.async_receive(net::as_tuple(net::use_awaitable));
            (void)wait_error;
        }
        if (stopping || (packet.owner->retired.load() && !packet.terminal)) {
            socket->sending.reset();
            socket->drained.cancel();
            continue;
        }
        auto [error, bytes] = co_await socket->socket->async_send_to(
            net::buffer(packet.data), packet.remote,
            net::as_tuple(net::use_awaitable));
        socket->sending.reset();
        socket->drained.cancel();
        (void)bytes;
        if (error == net::error::operation_aborted) co_return;
    }
}

void QuicListener::ArmExpiry() {
    memory::ScopedWorkerAllocation worker_allocation;
    ngtcp2_tstamp nearest = std::numeric_limits<ngtcp2_tstamp>::max();
    for (const auto& [id, connection] : connections) {
        (void)id;
        const auto& owner = connection->Ownership();
        if (!owner->retired.load() && !owner->claiming.load())
            nearest = std::min(nearest, owner->expiry.load());
    }
    if (nearest == std::numeric_limits<ngtcp2_tstamp>::max()) {
        expiry.expires_at(std::chrono::steady_clock::time_point::max());
        return;
    }
    expiry.expires_at(std::chrono::steady_clock::time_point(
        std::chrono::nanoseconds(nearest)));
    if (!expiry_running) {
        expiry_running = true;
        Spawn(ExpiryLoop());
    }
}

net::awaitable<void> QuicListener::ExpiryLoop() {
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
            if (!connection->Ownership()->claiming.load() &&
                connection->Ownership()->expiry.load() <= now &&
                std::find(unique.begin(), unique.end(), connection) ==
                    unique.end())
                unique.push_back(connection);
        }
        for (auto& connection : unique) {
            connection->Ownership()->expiry.store(std::numeric_limits<ngtcp2_tstamp>::max());
            connection->Ownership()->domain->Execute([connection] { connection->OnExpiry(); });
        }
        std::erase_if(connections, [](const auto& entry) {
            return !entry.second || entry.second->Ownership()->retired.load();
        });

        ngtcp2_tstamp nearest =
            std::numeric_limits<ngtcp2_tstamp>::max();
        for (const auto& [id, connection] : connections) {
            (void)id;
            const auto& owner = connection->Ownership();
            if (!owner->retired.load() && !owner->claiming.load())
                nearest = std::min(nearest, owner->expiry.load());
        }
        if (nearest == std::numeric_limits<ngtcp2_tstamp>::max()) break;
        expiry.expires_at(std::chrono::steady_clock::time_point(
            std::chrono::nanoseconds(nearest)));
    }
    expiry_running = false;
}

void QuicListener::Stop() noexcept {
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
    for (auto& [owner, inbox] : inboxes) {
        (void)owner;
        if (inbox->claim) inbox->claim->Notify();
    }
    for (auto& [owner, connection] : sessions) {
        (void)owner;
        connection->Ownership()->domain->Execute([connection, binding = identity] {
            if (connection->Ownership()->listener.load() == binding.get()) connection->Close();
        });
    }
}

HysteriaIngress::HysteriaIngress(
    uint32_t worker_id, net::io_context& io_context,
    app::DatagramSessionEnvironment environment)
    : listener_(std::make_unique<QuicListener>(
          worker_id, io_context, std::move(environment))) {}

HysteriaIngress::~HysteriaIngress() noexcept { RequestStop(); }

HysteriaIngress::SocketPtr HysteriaIngress::MakeSocket() {
    return memory::AllocateShared<udp::socket>(listener_->io);
}

HysteriaIngress::SocketPtr HysteriaIngress::AttachSocket(
    std::string_view socket_key, SocketPtr socket) {
    if (!socket || !socket->is_open() || listener_->started || listener_->stopping)
        return {};
    auto state = memory::AllocateShared<SocketState>(listener_->io);
    state->socket = std::move(socket);
    state->key.assign(socket_key);
    IoErrorCode error;
    state->local = state->socket->local_endpoint(error);
    if (error) return {};
    state->socket->non_blocking(true, error);
    if (error) return {};
    auto [it, inserted] = listener_->sockets.try_emplace(state->key, state);
    return inserted ? it->second->socket : SocketPtr{};
}

void HysteriaIngress::Start() {
    if (listener_->started || listener_->stopping) return;
    listener_->started = true;
    for (auto& [key, socket] : listener_->sockets) {
        (void)key;
        listener_->Spawn(listener_->ReceiveLoop(socket));
        listener_->Spawn(listener_->SendLoop(socket));
    }
}

void HysteriaIngress::RequestStop() noexcept {
    if (listener_) listener_->Stop();
}

net::awaitable<void> HysteriaIngress::AsyncJoin() {
    RequestStop();
    while (listener_->tasks != 0 || listener_->connection_tasks != 0) {
        auto [error] = co_await listener_->changed.async_wait(
            net::as_tuple(net::use_awaitable));
        (void)error;
    }
}

}  // namespace transport::internet::hysteria
