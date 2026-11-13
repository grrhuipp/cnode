#include "transport/hysteria_ingress.hpp"
#include "transport/hysteria_connection.hpp"
#include "transport/tls_stream.hpp"
#include "transport/link.hpp"
#include <linux/filter.h>
#include <sys/socket.h>
#include "common/scoped_cleanse.hpp"

#include "app/user_store.hpp"
#include "app/rate_limiter.hpp"
#include "app/group_coordinator.hpp"
#include "app/request_load.hpp"
#include "app/stats.hpp"
#include "common/multi_buffer.hpp"
#include "common/byte_reader.hpp"
#include "common/ip_address.hpp"
#include "common/allocator.hpp"
#include "common/session.hpp"
#include "common/user_online_tracker.hpp"
#include "common/hash.hpp"
#include "infra/config_types.hpp"
#include "infra/log.hpp"
#include "transport/transport_stack.hpp"
#include "transport/timeout_scheduler.hpp"
#include "proxy/inbound_admission.hpp"
#include "common/awaitable_task_group.hpp"
#include "transport/datagram_socket.hpp"
#include <nghttp3/nghttp3.h>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_boringssl.h>

#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>

#include <asio/as_tuple.hpp>
#include <asio/co_spawn.hpp>
#include <asio/steady_timer.hpp>
#include <asio/this_coro.hpp>
#include <asio/use_awaitable.hpp>

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <cstring>
#include <limits>
#include <new>
#include <optional>
#include <stdexcept>
#include <utility>
#include <cstdint>
#include <string>
#include <vector>

namespace transport {

ConnectionId::ConnectionId(const ngtcp2_cid& cid) noexcept
    : ConnectionId(cid.data, cid.datalen) {}

void EncodeWorkerServerCid(ngtcp2_cid& cid, size_t length, uint32_t worker_id) noexcept {
    cid.datalen = length;
    if (length >= 3) {
        cid.data[0] = kServerCidMagic0;
        cid.data[1] = kServerCidMagic1;
        cid.data[2] = static_cast<uint8_t>(worker_id);
    }
}

bool AttachQuicReuseportBpf(int fd, uint32_t worker_count) noexcept {
    if (worker_count == 0) return false;
    const uint32_t count = worker_count;
    // 长短头均识别签发的 DCID；其他 Initial 按随机 DCID 前缀散列。
    std::array<sock_filter, 15> instructions{{
        {BPF_LD | BPF_B | BPF_ABS, 0, 0, 0},
        {BPF_JMP | BPF_JSET | BPF_K, 4, 0, 0x80},
        {BPF_LD | BPF_H | BPF_ABS, 0, 0, 1},
        {BPF_JMP | BPF_JEQ | BPF_K, 0, 8, kServerCidMagicWord},
        {BPF_LD | BPF_B | BPF_ABS, 0, 0, 3},
        {BPF_JMP | BPF_JA, 0, 0, 5},
        {BPF_LD | BPF_B | BPF_ABS, 0, 0, 5},
        {BPF_JMP | BPF_JEQ | BPF_K, 0, 4, static_cast<uint32_t>(kServerConnectionIdLength)},
        {BPF_LD | BPF_H | BPF_ABS, 0, 0, 6},
        {BPF_JMP | BPF_JEQ | BPF_K, 0, 2, kServerCidMagicWord},
        {BPF_LD | BPF_B | BPF_ABS, 0, 0, 8},
        {BPF_JMP | BPF_JGE | BPF_K, 0, 2, count},
        {BPF_LD | BPF_W | BPF_ABS, 0, 0, 6},
        {BPF_ALU | BPF_MOD | BPF_K, 0, 0, count},
        {BPF_RET | BPF_A, 0, 0, 0},
    }};
    sock_fprog program{
        .len = static_cast<unsigned short>(instructions.size()),
        .filter = instructions.data(),
    };
    return ::setsockopt(fd, SOL_SOCKET, SO_ATTACH_REUSEPORT_CBPF,
                        &program, sizeof(program)) == 0;
}

namespace {


// The C libraries need realloc semantics; use mimalloc's native API directly.
void* AllocateQuicMemory(size_t size, void*) {
    return mi_malloc(size);
}

void FreeQuicMemory(void* pointer, void*) noexcept {
    mi_free(pointer);
}

void* CallocateQuicMemory(size_t count, size_t size, void*) {
    return mi_calloc(count, size);
}

void* ReallocateQuicMemory(void* pointer, size_t size, void*) {
    if (size == 0) {
        mi_free(pointer);
        return nullptr;
    }
    return mi_realloc(pointer, size);
}

const ngtcp2_mem kQuicMemory{
    nullptr, &AllocateQuicMemory, &FreeQuicMemory, &CallocateQuicMemory, &ReallocateQuicMemory};
const nghttp3_mem kHttp3Memory{
    nullptr, &AllocateQuicMemory, &FreeQuicMemory, &CallocateQuicMemory, &ReallocateQuicMemory};
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
static_assert(kMaxStreamOutputBytes <= UINT32_MAX);
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

[[nodiscard]] common::MultiBuffer CopyPacket(std::span<const uint8_t> bytes) {
    common::MultiBuffer output;
    if (!output.AppendSpan(bytes)) throw std::bad_alloc();
    return output;
}


}  // namespace


struct HysteriaSocketState final {
    explicit HysteriaSocketState(net::io_context& io)
        : changed(io, 1) {}
    HysteriaIngress::SocketPtr socket;
    udp::endpoint local;
    udp::endpoint remote;
    struct Output {
        std::vector<uint8_t> data;
        udp::endpoint remote;
        std::shared_ptr<HysteriaConnection> connection;
        bool terminal = false;
    };
    common::RingDeque<Output> output;
    common::SignalChannel changed;
};

const app::ReceiverSettings& HysteriaIngress::Receiver() const noexcept {
    return environment.handler->ReceiverSettings();
}

HysteriaConnection::HysteriaConnection(
    HysteriaIngress& listener, HysteriaSocketState& socket, const udp::endpoint& remote)
    : TimeoutEvent(listener.io)
    , listener_(&listener)
    , closed_signal_(listener.io.get_executor(), 1)
    , core_(std::in_place)
    , physical_ready_(listener.io.get_executor(), 1) {
    core_->local = socket.local;
    core_->remote = remote;
    InitializeBaseContext(remote);
}

net::io_context& HysteriaConnection::Reactor() const noexcept {
    return listener_->io;
}

std::shared_ptr<HysteriaConnection> HysteriaConnection::Create(
    HysteriaIngress& listener, HysteriaSocketState& socket,
    const udp::endpoint& remote, const ngtcp2_pkt_hd& header) {
    auto connection = std::shared_ptr<HysteriaConnection>(
        new HysteriaConnection(listener, socket, remote));
    if (!connection->Initialize(header)) return nullptr;
    bool tracked = false;
    try {
        listener.Associate(header.dcid, connection);
        listener.Associate(connection->core_->server_cid, connection);
        listener.sessions.emplace(connection.get(), connection);
        listener.environment.admission->stats.OnConnectionAccepted();
        connection->stats_open_ = true;
        ++listener.tasks;
        tracked = true;
        net::co_spawn(connection->Reactor(), connection->Run(),
            [connection](std::exception_ptr error) {
                auto* owner = connection->listener_;
                connection->Close();
                owner->sessions.erase(connection.get());
                common::MaybeShrinkHashContainer(owner->sessions);
                --owner->tasks;
                owner->changed.cancel();
                if (error && !common::IsOperationCancelled(error))
                    LOG_ERROR("Hysteria connection task failed worker={}", owner->worker_id);
            });
    } catch (...) {
        connection->Close();
        listener.sessions.erase(connection.get());
        common::MaybeShrinkHashContainer(listener.sessions);
        if (tracked) --listener.tasks;
        throw;
    }
    return connection;
}

void HysteriaConnection::Random(uint8_t* data, size_t length, const ngtcp2_rand_ctx*) {
    if (RAND_bytes(data, length) != 1) std::terminate();
}

int HysteriaConnection::NewConnectionId(ngtcp2_conn*, ngtcp2_cid* cid, uint8_t* token,
    size_t length, void* user_data) {
    auto& self = *static_cast<HysteriaConnection*>(user_data);
    if (RAND_bytes(cid->data, length) != 1) return NGTCP2_ERR_CALLBACK_FAILURE;
    EncodeWorkerServerCid(*cid, length, self.listener_->worker_id);
    if (RAND_bytes(token, NGTCP2_STATELESS_RESET_TOKENLEN) != 1)
        return NGTCP2_ERR_CALLBACK_FAILURE;
    try { self.listener_->Associate(*cid, self.shared_from_this()); }
    catch (...) { return NGTCP2_ERR_CALLBACK_FAILURE; }
    return 0;
}

int HysteriaConnection::RemoveConnectionId(ngtcp2_conn*, const ngtcp2_cid* cid,
    void* user_data) {
    auto& self = *static_cast<HysteriaConnection*>(user_data);
    self.listener_->Dissociate(*cid);
    std::erase(self.connection_ids_, ConnectionId(*cid));
    return 0;
}

int HysteriaConnection::UpdateKey(ngtcp2_conn* conn, uint8_t* rx_secret,
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

int HysteriaConnection::ReceiveTxKey(ngtcp2_conn*, ngtcp2_encryption_level level,
    void* user_data) {
    auto& self = *static_cast<HysteriaConnection*>(user_data);
    return level == NGTCP2_ENCRYPTION_LEVEL_1RTT &&
           self.listener_->version == HysteriaVersion::V2 && !self.SetupHttp3()
        ? NGTCP2_ERR_CALLBACK_FAILURE : 0;
}

int HysteriaConnection::ReceiveDatagram(ngtcp2_conn*, uint32_t flags,
    const uint8_t* data, size_t length, void* user_data) {
    auto& self = *static_cast<HysteriaConnection*>(user_data);
    if ((flags & NGTCP2_DATAGRAM_FLAG_0RTT) || !self.authenticated_)
        return 0;
    auto message = ParseUdpMessage(self.listener_->version, {data, length});
    if (message) self.ProcessUdpMessage(*message);
    return 0;
}

void HysteriaConnection::InitializeBaseContext(const udp::endpoint& remote) {
    const auto& receiver = listener_->Receiver();
    base_context_.conn_id = common::NewID(listener_->worker_id);
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
            tcp::endpoint(common::NormalizeAddress(local.address()), local.port());
    }
    const auto source = common::NormalizeAddress(remote.address());
    base_context_.inbound.source_addr = source;
    base_context_.inbound.source_ip = common::AddressText(source).View();
    base_context_.inbound.source_port = remote.port();
}

bool HysteriaConnection::Initialize(const ngtcp2_pkt_hd& header) {
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
            &kQuicMemory, this) != 0)
        return false;

    core_->conn_ref = {&GetConn, this};
    core_->ssl = SSL_new(listener_->ssl_context->Native());
    if (!core_->ssl) return false;
    SSL_set_app_data(core_->ssl, &core_->conn_ref);
    SSL_set_accept_state(core_->ssl);
    ngtcp2_conn_set_tls_native_handle(core_->quic, core_->ssl);
    return true;
}

void HysteriaConnection::SpawnOwned(net::awaitable<void> task) {
    tasks_->Spawn([](std::shared_ptr<HysteriaConnection> owner, net::awaitable<void> request)
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

net::awaitable<void> HysteriaConnection::Run() {
    std::exception_ptr failure;
    app::RequestLoadState::PhysicalConnectionScope physical(*listener_->environment.request_load);
    try {
        co_await common::RunAwaitableTaskGroup(Reactor().get_executor(), [&](common::AwaitableTaskGroup& tasks) {
            tasks_ = &tasks;
            tasks.Spawn(WaitClosed());
            tasks.Spawn(ReservePhysicalAdmission());
        });
    } catch (...) { failure = std::current_exception(); }
    Close();
    tasks_ = nullptr;
    core_.reset();
    if (failure) std::rethrow_exception(failure);
}

net::awaitable<void> HysteriaConnection::WaitClosed() {
    if (!closed_) {
        auto [error] = co_await closed_signal_.async_receive(
            net::as_tuple(net::use_awaitable));
        (void)error;
    }
    Close();
    if (tasks_) tasks_->Cancel();
}

HysteriaSocketState* HysteriaConnection::OutputSocket(const ngtcp2_path& path) const noexcept {
    if (path.user_data != &core_->path_binding) return nullptr;
    auto local = EndpointFromAddress(path.local);
    return local ? listener_->Resolve(*local) : nullptr;
}

void HysteriaConnection::PublishExpiry() noexcept {
    if (closed_) return;
    const auto deadline = Expiry();
    if (deadline == std::numeric_limits<ngtcp2_tstamp>::max()) {
        TimeoutEvent::Cancel();
        return;
    }
    const auto now = Timestamp();
    const auto remaining = std::min<ngtcp2_tstamp>(
        deadline > now ? deadline - now : 0,
        std::chrono::nanoseconds::max().count());
    const auto delay = std::chrono::ceil<std::chrono::milliseconds>(
        std::chrono::nanoseconds(remaining));
    try {
        if (!ScheduleAfter(delay)) Close();
    } catch (...) {
        Close();
    }
}

void HysteriaConnection::OnTimeout() {
    // 到期回调可能关闭连接，整个回调期间固定其寿命。
    auto keep_alive = shared_from_this();
    try {
        OnExpiry();
    } catch (...) {
        const auto reason = transport::ClassifyFailure(
            std::current_exception(), common::ErrorCode::INTERNAL);
        Close();
        listener_->environment.admission->stats.OnError();
        try {
            LOG_ERROR("Hysteria expiry failed worker={} > {}",
                      listener_->worker_id, common::ErrorCodeToString(reason));
        } catch (...) {}
    }
}

int HysteriaConnection::PathValidated(ngtcp2_conn*, uint32_t,
    const ngtcp2_path* path, const ngtcp2_path*,
    ngtcp2_path_validation_result result, void* user_data) {
    auto& self = *static_cast<HysteriaConnection*>(user_data);
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
                common::AddressText(remote->address()).View(), remote->port());
        } catch (...) {}
    }
    return 0;
}

void HysteriaConnection::Feed(HysteriaSocketState& socket, const udp::endpoint& remote,
                      std::span<const uint8_t> packet) {
    if (!core_ || closed_) return;
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
            listener_->environment.admission->stats.OnError();
        Close();
        return;
    }
    if (foreign_path) {
        ngtcp2_conn_info info{};
        ngtcp2_conn_get_conn_info(core_->quic, &info);
        if (info.pkt_recv == packets_received) {
            try {
                LOG_DEBUG("QUIC path packet rejected receiving_worker={} remote={}:{} reason=no-path-evidence",
                    listener_->worker_id, common::AddressText(remote.address()).View(), remote.port());
            } catch (...) {}
            return;
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
                    common::AddressText(selected_remote->address()).View(),
                    selected_remote->port());
            } catch (...) {}
        }
    }
    Flush();
}

void HysteriaConnection::OnExpiry() {
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

void HysteriaConnection::ScheduleStreamOutput(int64_t stream_id, StreamRecord& stream) noexcept {
    if (stream.output_next >= 0 || !stream.state->Open() || stream.flow_blocked ||
        (stream.output_index == stream.output.size() && !stream.fin_pending))
        return;
    if (core_->next_output_stream < 0) {
        stream.output_previous = stream_id;
        stream.output_next = stream_id;
        core_->next_output_stream = stream_id;
        return;
    }
    auto& head = core_->streams.find(core_->next_output_stream)->second;
    auto& tail = core_->streams.find(head.output_previous)->second;
    stream.output_previous = head.output_previous;
    stream.output_next = core_->next_output_stream;
    tail.output_next = stream_id;
    head.output_previous = stream_id;
}

void HysteriaConnection::UnscheduleStreamOutput(int64_t stream_id, StreamRecord& stream) noexcept {
    if (stream.output_next < 0) return;
    if (stream.output_next == stream_id) {
        core_->next_output_stream = -1;
    } else {
        core_->streams.find(stream.output_previous)->second.output_next = stream.output_next;
        core_->streams.find(stream.output_next)->second.output_previous = stream.output_previous;
        if (core_->next_output_stream == stream_id)
            core_->next_output_stream = stream.output_next;
    }
    stream.output_previous = -1;
    stream.output_next = -1;
}

std::shared_ptr<QuicStreamState> HysteriaConnection::QueueStreamOutput(
    int64_t stream_id, common::MultiBuffer& payload) {
    if (!core_ || closed_)
        throw transport::LinkError(common::ErrorCode::CONNECTION_CLOSED);
    auto it = core_->streams.find(stream_id);
    if (it == core_->streams.end())
        throw transport::LinkError(common::ErrorCode::CONNECTION_CLOSED);
    auto& stream = it->second;
    stream.state->CheckWriteOpen();
    const size_t bytes = payload.byte_size();
    if (bytes > kMaxStreamOutputBytes)
        throw transport::LinkError(common::ErrorCode::RESOURCE_EXHAUSTED);
    if (stream.queued_bytes > kMaxStreamOutputBytes - bytes) return stream.state;
    if (bytes != 0) {
        stream.output.push_back(std::move(payload));
    }
    stream.queued_bytes += bytes;
    ScheduleStreamOutput(stream_id, stream);
    Flush();
    return nullptr;
}

void HysteriaConnection::ConsumeStream(int64_t stream_id, size_t bytes) noexcept {
    if (!core_ || closed_) return;
    ngtcp2_conn_extend_max_stream_offset(core_->quic, stream_id, bytes);
    ngtcp2_conn_extend_max_offset(core_->quic, bytes);
    Flush();
}

void HysteriaConnection::ShutdownStreamWrite(int64_t stream_id) noexcept {
    if (!core_ || closed_) return;
    auto it = core_->streams.find(stream_id);
    if (it == core_->streams.end()) return;
    it->second.fin_pending = true;
    ScheduleStreamOutput(stream_id, it->second);
    Flush();
}

void HysteriaConnection::CancelStream(int64_t stream_id) noexcept {
    if (!core_ || closed_) return;
    std::shared_ptr<QuicStreamState> state;
    {
        auto it = core_->streams.find(stream_id);
        if (it != core_->streams.end()) {
            UnscheduleStreamOutput(stream_id, it->second);
            state = it->second.state;
        }
    }
    if (state) state->RemoteReset();
    if (closed_) return;
    ngtcp2_conn_shutdown_stream(core_->quic, 0, stream_id, 0);
    Flush();
}

int HysteriaConnection::AckStreamData(ngtcp2_conn*, int64_t stream_id, uint64_t offset,
    uint64_t length, void* user_data, void*) {
    auto& self = *static_cast<HysteriaConnection*>(user_data);
    if (self.core_->http &&
        (!ngtcp2_is_bidi_stream(stream_id) ||
         self.core_->h3_requests.contains(stream_id)))
        return nghttp3_conn_add_ack_offset(
            self.core_->http, stream_id, length) == 0
            ? 0 : NGTCP2_ERR_CALLBACK_FAILURE;
    auto it = self.core_->streams.find(stream_id);
    if (it == self.core_->streams.end() || length == 0) return 0;
    auto& stream = it->second;
    // ngtcp2 reports the newly acknowledged contiguous prefix, even when wire
    // ACKs arrive out of order (ngtcp2_callbacks::acked_stream_data_offset).
    size_t released = static_cast<size_t>(length);
    stream.queued_bytes -= std::min(stream.queued_bytes, released);
    while (released != 0 && !stream.output.empty()) {
        const size_t dropped =
            stream.output.front().DropPrefixBytes(released);
        released -= dropped;
        if (stream.output_index == 0)
            stream.output_offset -= static_cast<uint32_t>(
                std::min<size_t>(stream.output_offset, dropped));
        if (stream.output.front().empty()) {
            stream.output.pop_front();
            if (stream.output_index != 0) --stream.output_index;
        }
        if (dropped == 0) break;
    }
    stream.state->NotifyWritable();
    return 0;
}

int HysteriaConnection::OpenStream(ngtcp2_conn*, int64_t stream_id, void* user_data) {
    auto& self = *static_cast<HysteriaConnection*>(user_data);
    if (!ngtcp2_is_bidi_stream(stream_id)) return 0;
    auto state = std::make_shared<QuicStreamState>(
        self.Reactor(), stream_id, self.weak_from_this());
    auto [it, inserted] = self.core_->streams.try_emplace(
        stream_id, std::move(state));
    if (!inserted) return NGTCP2_ERR_CALLBACK_FAILURE;
    const auto version = self.listener_->version;
    if (version == HysteriaVersion::V1 && stream_id == 0) {
        self.SpawnOwned(self.RunV1Control(stream_id));
    } else if (version == HysteriaVersion::V2 && !self.authenticated_) {
        self.core_->h3_requests.try_emplace(stream_id);
    } else {
        it->second.raw = true;
        if (self.authenticated_) self.StartRawStream(stream_id, it->second);
    }
    return 0;
}

int HysteriaConnection::CloseStream(ngtcp2_conn* conn, uint32_t flags, int64_t stream_id,
    uint64_t app_error_code, void* user_data, void*) {
    auto& self = *static_cast<HysteriaConnection*>(user_data);
    auto h3_it = self.core_->h3_requests.find(stream_id);
    if (self.core_->http &&
        (!ngtcp2_is_bidi_stream(stream_id) ||
         h3_it != self.core_->h3_requests.end())) {
        const int result = nghttp3_conn_close_stream(
            self.core_->http, stream_id, app_error_code);
        if (result != 0 && result != NGHTTP3_ERR_STREAM_NOT_FOUND)
            return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    std::shared_ptr<QuicStreamState> state;
    if (auto it = self.core_->streams.find(stream_id);
        it != self.core_->streams.end()) {
        self.UnscheduleStreamOutput(stream_id, it->second);
        state = std::move(it->second.state);
        self.core_->streams.erase(it);
        common::MaybeShrinkHashContainer(self.core_->streams, 8);
    }
    if (h3_it != self.core_->h3_requests.end()) {
        self.core_->h3_requests.erase(h3_it);
        common::MaybeShrinkHashContainer(self.core_->h3_requests, 8);
    }
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

int HysteriaConnection::ResetStream(ngtcp2_conn*, int64_t stream_id, uint64_t,
    uint64_t, void* user_data, void*) {
    // RESET_STREAM is not stream_close: ngtcp2 may still borrow output for
    // the opposite direction until its actual close callback.
    auto& self = *static_cast<HysteriaConnection*>(user_data);
    if (self.core_->http &&
        (!ngtcp2_is_bidi_stream(stream_id) ||
         self.core_->h3_requests.contains(stream_id))) {
        return nghttp3_conn_shutdown_stream_read(self.core_->http, stream_id) == 0
            ? 0 : NGTCP2_ERR_CALLBACK_FAILURE;
    }
    self.CancelStream(stream_id);
    return 0;
}

int HysteriaConnection::StopSending(ngtcp2_conn*, int64_t stream_id, uint64_t,
    void* user_data, void*) {
    // This callback reports local read shutdown, not a peer STOP_SENDING.
    auto& self = *static_cast<HysteriaConnection*>(user_data);
    if (self.core_->http &&
        (!ngtcp2_is_bidi_stream(stream_id) ||
         self.core_->h3_requests.contains(stream_id))) {
        return nghttp3_conn_shutdown_stream_read(self.core_->http, stream_id) == 0
            ? 0 : NGTCP2_ERR_CALLBACK_FAILURE;
    }
    self.CancelStream(stream_id);
    return 0;
}

void HysteriaConnection::Flush() {
    if (!core_ || closed_ || in_ngtcp2_callback_) return;
    // ngtcp2 can retire streams while encoding packets as well as receiving
    // them. Credit and cancellation callbacks must not start a nested write.
    in_ngtcp2_callback_ = true;
    struct RefreshExpiry {
        HysteriaConnection& connection;
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
    const auto local = MakeAddress(core_->local);
    const auto remote = MakeAddress(core_->remote);
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
        auto stream_it = core_->streams.end();
        if (!http_data && core_->next_output_stream >= 0) {
            stream_id = core_->next_output_stream;
            stream_it = core_->streams.find(stream_id);
            auto& stream = stream_it->second;
            const bool has_unsent = stream.output_index < stream.output.size();
            if (!stream.state->Open() || stream.flow_blocked ||
                (!has_unsent && !stream.fin_pending)) {
                UnscheduleStreamOutput(stream_id, stream);
                continue;
            }
            core_->next_output_stream = stream.output_next;
            fin = stream.fin_pending && !has_unsent;
            size_t skip = stream.output_offset;
            for (size_t output_index = stream.output_index;
                 output_index < stream.output.size(); ++output_index) {
                auto bytes = stream.output[output_index].FrontSpan();
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
        }
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
                    *output_remote, *this)) {
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
            } else if (stream_it != core_->streams.end()) {
                if (written == NGTCP2_ERR_STREAM_DATA_BLOCKED) {
                    stream_it->second.flow_blocked = true;
                    UnscheduleStreamOutput(stream_id, stream_it->second);
                } else {
                    auto state = stream_it->second.state;
                    UnscheduleStreamOutput(stream_id, stream_it->second);
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
            } else if (stream_it != core_->streams.end()) {
                auto& stream = stream_it->second;
                size_t remaining = static_cast<size_t>(accepted);
                while (remaining != 0) {
                    const size_t available =
                        stream.output[stream.output_index].byte_size() - stream.output_offset;
                    if (remaining < available) {
                        stream.output_offset += static_cast<uint32_t>(remaining);
                        break;
                    }
                    remaining -= available;
                    ++stream.output_index;
                    stream.output_offset = 0;
                }
                if (fin) stream.fin_pending = false;
                if (stream.output_index == stream.output.size() && !stream.fin_pending)
                    UnscheduleStreamOutput(stream_id, stream);
            }
        }
        auto* output_socket = OutputSocket(write_path.path);
        auto output_remote = EndpointFromAddress(write_path.path.remote);
        if (!output_socket || !output_remote ||
            !listener_->Queue(*output_socket,
                std::span<const uint8_t>(packet.data(), static_cast<size_t>(written)),
                *output_remote, *this)) {
            Close();
            return;
        }
        ++packets;
    }
}

void HysteriaConnection::Close() noexcept {
    if (closed_) return;
    closed_ = true;
    TimeoutEvent::Cancel();
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
        listener_->environment.admission->stats.OnConnectionClosed();
        stats_open_ = false;
    }
    stream_sink_.reset();
    online_session_.reset();
    physical_reservation_ = {};
    (void)closed_signal_.try_send(IoErrorCode{});
}

net::awaitable<void> HysteriaConnection::ReservePhysicalAdmission() {
    app::ConnectionLimiter::Admission admission;
    if (auto pending = proxy::ReserveInboundConnection(
            *listener_->environment.admission, app::ConnectionLimiter::ReservationScope::Physical, base_context_)) {
        admission = co_await std::move(*pending);
    }
    const auto reject = admission.reason;
    if (closed_) co_return;
    if (reject != app::ConnectionLimiter::RejectReason::NONE) {
        proxy::RejectInboundAdmission(base_context_, listener_->environment.admission->stats, reject);
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
void HysteriaConnection::Refuse() noexcept {
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
                        core_->remote, *this, true);
            } catch (const std::bad_alloc&) {
                // The close frame is advisory; state is dropped regardless.
            }
        }
    }
    Close();
}

net::awaitable<HysteriaConnection::AdmitResult> HysteriaConnection::AdmitConnection(
    std::string_view credential) {
    auto auth_hash = HashCredential(credential);
    common::ScopedCleanse cleanse_auth_hash{auth_hash};
    while (physical_ == PhysicalAdmission::Pending && !closed_) {
        auto [error] = co_await physical_ready_.async_receive(
            net::as_tuple(net::use_awaitable));
        if (error) co_return AdmitResult::Limited;
    }
    if (closed_ || physical_ != PhysicalAdmission::Admitted)
        co_return AdmitResult::Limited;
    auto authentication = co_await proxy::BeginInboundAuthentication(*listener_->environment.admission, base_context_);
    if (!authentication) {
        if (authentication.error() != common::ErrorCode::CANCELLED && authentication.error() != common::ErrorCode::SOCKET_EOF)
            listener_->environment.admission->stats.OnError();
        co_return AdmitResult::Limited;
    }
    const auto credential_check = co_await authentication->VerifyCredential({proxy::KeyedInboundProtocol::Hysteria, auth_hash});
    if (credential_check != common::ErrorCode::OK) {
        if (credential_check != common::ErrorCode::CANCELLED && credential_check != common::ErrorCode::SOCKET_EOF)
            listener_->environment.admission->stats.OnError();
        co_return AdmitResult::Limited;
    }
    if (closed_) co_return AdmitResult::Limited;
    const auto& receiver = listener_->Receiver();
    auto user = app::UserStore::FindHysteriaUser(
        receiver.inbound_tag, auth_hash);
    const auto profile = user ? std::optional<common::UserProfile>(user->profile) : std::nullopt;
    user.reset();
    auto session = co_await proxy::AuthenticateAndAdmit(
        std::move(*authentication), profile ? &*profile : nullptr, "no matching credential", std::nullopt);
    if (!session) {
        if (session.error() != common::ErrorCode::CANCELLED && session.error() != common::ErrorCode::SOCKET_EOF)
            listener_->environment.admission->stats.OnError();
        if (session.error() == common::ErrorCode::PROTOCOL_AUTH_FAILED) co_return AdmitResult::AuthFailed;
        co_return session.error() == common::ErrorCode::PERMISSION_DENIED
            ? AdmitResult::DeviceLimited : AdmitResult::Limited;
    }
    if (closed_) co_return AdmitResult::Limited;
    online_session_.emplace(std::move(*session));
    stream_sink_ = listener_->environment.handler->NewAuthenticatedStreamSink(
        Reactor(), *listener_->environment.dispatcher, listener_->environment.admission->stats,
        *listener_->environment.request_load, listener_->environment.timeouts,
        base_context_, physical_reservation_.FamilyLease());
    authenticated_ = true;
    co_return AdmitResult::Admitted;
}

void HysteriaConnection::OnStreamData(
    uint32_t flags, int64_t stream_id, std::span<const uint8_t> data) {
    const bool fin = (flags & NGTCP2_STREAM_DATA_FLAG_FIN) != 0;
    auto it = core_->streams.find(stream_id);
    if (listener_->version == HysteriaVersion::V2 &&
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
void HysteriaConnection::StartRawStream(int64_t stream_id, StreamRecord& stream) {
    if (stream.delivered) return;
    if (listener_->version == HysteriaVersion::V1) {
        const auto& input = stream.state->PendingInput();
        const auto front = input.FrontSpan();
        if (front.empty()) return;
        if (front[0] != 0) {
            const size_t inspect_bytes =
                std::min(input.byte_size(), kMaxStreamHeaderBytes);
            auto request = ParseV1Request(input.PrefixSpan(inspect_bytes));
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
    SpawnOwned(DeliverStream(std::make_unique<QuicStream>(stream.state), {}));
}

void HysteriaConnection::OpenV1UdpSession(
    int64_t stream_id, StreamRecord& stream, size_t header_bytes) {
    const uint32_t session_id = next_udp_session_id_++;
    if (session_id == 0 || core_->udp_sessions.size() >= kMaxUdpSessions) {
        CancelStream(stream_id);
        return;
    }
    stream.delivered = true;
    stream.state->DiscardInput(header_bytes);
    std::array<uint8_t, 7> response;
    const size_t response_size = EncodeV1ResponseTo(response, true, session_id, "");
    stream.output.push_back(CopyPacket({response.data(), response_size}));
    stream.queued_bytes += response_size;
    ScheduleStreamOutput(stream_id, stream);
    Flush();
}

net::awaitable<void> HysteriaConnection::DeliverStream(
    std::unique_ptr<AsyncStream> stream, InboundTransportMetadata metadata) {
    auto sink = stream_sink_;
    if (!sink) co_return;
    co_await sink->OnInboundTransportStream(std::move(stream), std::move(metadata));
}

net::awaitable<void> HysteriaConnection::RunV1Control(int64_t stream_id) {
    auto it = core_->streams.find(stream_id);
    if (it == core_->streams.end()) co_return;
    auto state = it->second.state;
    constexpr size_t kMaxHelloBytes = kMaxAuthLength + 32;
    common::MultiBuffer hello_bytes;
    tl::expected<V1ClientHello, ProtocolError> hello =
        tl::unexpected(ProtocolError::Incomplete);
    while (!hello) {
        auto chunk = co_await state->ReadMultiBuffer();
        const size_t bytes = chunk.byte_size();
        if (bytes == 0 || bytes > kMaxHelloBytes - hello_bytes.byte_size()) co_return;
        chunk.MoveTo(hello_bytes, true);
        hello = ParseV1ClientHello(hello_bytes.FrontSpan());
        if (!hello && hello.error() != ProtocolError::Incomplete) co_return;
    }
    const auto result = co_await AdmitConnection(hello->auth);
    hello_bytes.clear();
    if (result == AdmitResult::AuthFailed) {
        std::array<uint8_t, 64> response;
        const size_t size = EncodeV1ServerHelloTo(
            response, false, 0, 0, "authentication failed");
        co_await state->WriteMultiBuffer(CopyPacket({response.data(), size}));
        co_return;
    }
    if (result != AdmitResult::Admitted) co_return;
    {
        std::array<uint8_t, 32> response;
        const size_t size = EncodeV1ServerHelloTo(
            response, true, listener_->download_bytes_per_second,
            listener_->upload_bytes_per_second, "");
        co_await state->WriteMultiBuffer(CopyPacket({response.data(), size}));
    }
    if (closed_) co_return;
    std::vector<int64_t> waiting;
    for (const auto& [id, candidate] : core_->streams) {
        if (candidate.raw && !candidate.delivered) waiting.push_back(id);
    }
    for (const auto id : waiting) {
        if (closed_) co_return;
        if (auto found = core_->streams.find(id); found != core_->streams.end())
            StartRawStream(id, found->second);
    }
}

bool HysteriaConnection::SetupHttp3() {
    if (core_->http) return true;
    nghttp3_callbacks callbacks{};
    callbacks.begin_headers = [](nghttp3_conn*, int64_t stream_id,
        void* user_data, void*) {
        auto& self = *static_cast<HysteriaConnection*>(user_data);
        self.core_->h3_requests.insert_or_assign(stream_id, H3Request{});
        return 0;
    };
    callbacks.recv_header = [](nghttp3_conn*, int64_t stream_id, int32_t token,
        nghttp3_rcbuf* name, nghttp3_rcbuf* value, uint8_t,
        void* user_data, void*) {
        static_cast<HysteriaConnection*>(user_data)->OnHttpHeader(
            stream_id, token, name, value);
        return 0;
    };
    callbacks.end_headers = [](nghttp3_conn*, int64_t stream_id, int,
        void* user_data, void*) {
        auto& self = *static_cast<HysteriaConnection*>(user_data);
        self.SpawnOwned(self.AuthenticateV2(stream_id));
        return 0;
    };
    callbacks.stop_sending = [](nghttp3_conn*, int64_t stream_id,
        uint64_t code, void* user_data, void*) {
        return ngtcp2_conn_shutdown_stream_read(
            static_cast<HysteriaConnection*>(user_data)->core_->quic,
            0, stream_id, code);
    };
    callbacks.reset_stream = [](nghttp3_conn*, int64_t stream_id,
        uint64_t code, void* user_data, void*) {
        return ngtcp2_conn_shutdown_stream_write(
            static_cast<HysteriaConnection*>(user_data)->core_->quic,
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
            &kHttp3Memory, this) != 0) return false;
    nghttp3_conn_set_max_client_streams_bidi(core_->http, kMaxStreams);
    int64_t control = -1, encoder = -1, decoder = -1;
    return ngtcp2_conn_open_uni_stream(core_->quic, &control, nullptr) == 0 &&
           nghttp3_conn_bind_control_stream(core_->http, control) == 0 &&
           ngtcp2_conn_open_uni_stream(core_->quic, &encoder, nullptr) == 0 &&
           ngtcp2_conn_open_uni_stream(core_->quic, &decoder, nullptr) == 0 &&
           nghttp3_conn_bind_qpack_streams(core_->http, encoder, decoder) == 0;
}

void HysteriaConnection::OnHttpHeader(int64_t stream_id, int32_t token,
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

void HysteriaConnection::SubmitHttpStatus(
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

net::awaitable<void> HysteriaConnection::AuthenticateV2(int64_t stream_id) {
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

void HysteriaConnection::ExpireUdpFragments(ngtcp2_tstamp now) noexcept {
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
        std::unordered_map<uint64_t, PendingFragments>{}.swap(fragments_);
    }
}

bool UdpSessionStream::CanAcceptBytes(size_t total_bytes) const noexcept {
    if (closed_ || cancelled_) return false;
    // Datagrams cannot share a block. Count rounded capacity before allocating,
    // without subtracting an externally sized payload from the byte budget.
    const size_t buffer_count = total_bytes == 0
        ? 1 : 1 + (total_bytes - 1) / common::Buffer::kSize;
    return buffer_count <= kMaxQueuedBytes / common::Buffer::kSize - queued_buffer_count_;
}

bool UdpSessionStream::PushMultiBuffer(
    const common::TargetAddress& target, common::MultiBuffer packet) {
    const size_t total_bytes = packet.byte_size();
    if (!CanAcceptBytes(total_bytes)) return false;
    if (!common::SetUdpTarget(packet, target)) return false;
    const size_t buffer_count = total_bytes == 0
        ? 1 : 1 + (total_bytes - 1) / common::Buffer::kSize;
    input_.push_back(std::move(packet));
    queued_buffer_count_ += buffer_count;
    WakeReader();
    return true;
}

void HysteriaConnection::DeliverUdpMultiBuffer(
    uint32_t session_id, const common::TargetAddress& target,
    common::MultiBuffer packet) {
    if (auto it = core_->udp_sessions.find(session_id);
        it != core_->udp_sessions.end()) {
        (void)it->second->PushMultiBuffer(target, std::move(packet));
        return;
    }
    if (core_->udp_sessions.size() >= kMaxUdpSessions) return;
    auto session = std::make_unique<UdpSessionStream>(
        Reactor(), session_id, weak_from_this());
    if (!session->PushMultiBuffer(target, std::move(packet))) return;
    core_->udp_sessions.emplace(session_id, session.get());
    SpawnOwned(DeliverStream(std::move(session),
        InboundTransportMetadata{.real_ip = {}, .udp_session_target = target}));
}

void HysteriaConnection::ProcessUdpMessage(const HysteriaUdpMessage& message) {
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
    pending.received_fragments.set(message.fragment_id);
    if (message.fragment_id == pending.next_in_order) {
        if (!message.payload.empty() &&
            !pending.in_order.AppendSpan(message.payload)) {
            fragments_.erase(it);
            ExpireUdpFragments(now);
            return;
        }
        ++pending.next_in_order;
        while (pending.next_in_order < pending.count &&
               pending.received_fragments.test(pending.next_in_order)) {
            const uint8_t want = static_cast<uint8_t>(pending.next_in_order);
            auto staged = std::find_if(
                pending.out_of_order.begin(), pending.out_of_order.end(),
                [want](const StagedFragment& entry) { return entry.id == want; });
            if (staged != pending.out_of_order.end()) {
                if (!pending.in_order.AppendSpan(staged->payload)) {
                    fragments_.erase(it);
                    ExpireUdpFragments(now);
                    return;
                }
                *staged = std::move(pending.out_of_order.back());
                pending.out_of_order.pop_back();
            }
            ++pending.next_in_order;
        }
    } else if (!message.payload.empty()) {
        pending.out_of_order.push_back(StagedFragment{
            .id = message.fragment_id,
            .payload = {message.payload.begin(), message.payload.end()},
        });
    }
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
    common::TargetAddress target = std::move(pending.target);
    common::MultiBuffer assembled = std::move(pending.in_order);
    fragments_.erase(it);
    ExpireUdpFragments(now);
    DeliverUdpMultiBuffer(message.session_id, target, std::move(assembled));
}

void HysteriaConnection::DeliverUdpPacket(
    uint32_t session_id, const common::TargetAddress& target,
    std::span<const uint8_t> payload) {
    if (auto it = core_->udp_sessions.find(session_id);
        it != core_->udp_sessions.end()) {
        (void)it->second->Push(target, payload);
        return;
    }
    if (core_->udp_sessions.size() >= kMaxUdpSessions) return;
    auto session = std::make_unique<UdpSessionStream>(
        Reactor(), session_id, weak_from_this());
    if (!session->Push(target, payload)) return;
    core_->udp_sessions.emplace(session_id, session.get());
    SpawnOwned(DeliverStream(std::move(session),
        InboundTransportMetadata{.real_ip = {}, .udp_session_target = target}));
}

bool HysteriaConnection::TrySendImmediateDatagram(
    std::span<const uint8_t> header, std::span<const uint8_t> payload) {
    if (!core_ || closed_ || in_ngtcp2_callback_) return false;
    in_ngtcp2_callback_ = true;
    struct RefreshExpiry {
        HysteriaConnection& connection;
        ~RefreshExpiry() {
            if (connection.core_ && connection.core_->quic) {
                ngtcp2_conn_update_pkt_tx_time(connection.core_->quic, Timestamp());
            }
            connection.in_ngtcp2_callback_ = false;
            connection.PublishExpiry();
        }
    } refresh{*this};
    auto local = MakeAddress(core_->local);
    auto remote = MakeAddress(core_->remote);
    ngtcp2_path_storage write_path{};
    ngtcp2_path_storage_init(
        &write_path, local.addr, local.addrlen, remote.addr, remote.addrlen,
        &core_->path_binding);
    ngtcp2_pkt_info packet_info{};
    std::array<uint8_t, NGTCP2_MAX_UDP_PAYLOAD_SIZE> packet;
    std::array<ngtcp2_vec, 2> vectors{{
        {const_cast<uint8_t*>(header.data()), header.size()},
        {const_cast<uint8_t*>(payload.data()), payload.size()},
    }};
    const size_t vec_count = payload.empty() ? 1 : 2;
    int accepted_datagram = 0;
    const auto written = ngtcp2_conn_writev_datagram(
        core_->quic, &write_path.path, &packet_info, packet.data(), packet.size(),
        &accepted_datagram, NGTCP2_WRITE_DATAGRAM_FLAG_NONE, 0,
        vectors.data(), vec_count, Timestamp());
    if (written < 0) {
        if (written != NGTCP2_ERR_INVALID_STATE) Close();
        return written != NGTCP2_ERR_INVALID_STATE;
    }
    if (written > 0) {
        auto* output_socket = OutputSocket(write_path.path);
        auto output_remote = EndpointFromAddress(write_path.path.remote);
        if (!output_socket || !output_remote ||
            !listener_->Queue(*output_socket,
                std::span<const uint8_t>(packet.data(), static_cast<size_t>(written)),
                *output_remote, *this)) {
            Close();
            return true;
        }
    }
    return accepted_datagram != 0;
}

bool HysteriaConnection::SendUdpMessage(
    uint32_t session_id, const common::TargetAddress& target,
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
    std::optional<common::AddressText> address_storage;
    const auto text = PrepareUdpTargetText(version, target, address_storage);
    if (!text) return false;
    const auto header_size = UdpTargetHeaderSize(version, *text);
    if (!header_size || *header_size > message_budget) return false;
    const size_t fragment_payload = message_budget - *header_size;
    if (!payload.empty() && fragment_payload == 0) return false;
    const size_t fragments = payload.empty()
        ? 1 : 1 + (payload.size() - 1) / fragment_payload;
    if (fragments > std::numeric_limits<uint8_t>::max()) return false;
    if (core_->datagrams.size() >= kMaxQueuedDatagrams ||
        fragments > kMaxQueuedDatagrams - core_->datagrams.size()) return false;
    const size_t initial_datagrams = core_->datagrams.size();
    HysteriaUdpMessage message{
        .session_id = session_id,
        .packet_id = next_udp_packet_id_++,
        .fragment_count = static_cast<uint8_t>(fragments),
        .target = {},
        .payload = {},
    };
    // The first fragment always carries the target.
    if (text->host.empty()) return false;
    if (fragments == 1 && core_->datagrams.empty()) {
        message.fragment_id = 0;
        message.payload = payload;
        // Valid TargetAddress host <= 254B, so V1 header <= 268B and V2 <= 272B.
        constexpr size_t kMaxUdpTargetHeaderBufSize = 280;
        std::array<uint8_t, kMaxUdpTargetHeaderBufSize> header_buf;
        if (*header_size > header_buf.size()) return false;
        const auto hdr_len = EncodeUdpFragmentHeader(
            version, message, *text,
            std::span<uint8_t>(header_buf.data(), *header_size));
        if (!hdr_len) return false;
        const std::span<const uint8_t> header_span(header_buf.data(), *hdr_len);
        if (TrySendImmediateDatagram(header_span, payload)) {
            if (!closed_ &&
                (core_->http || core_->next_output_stream >= 0 || !core_->datagrams.empty())) {
                Flush();
            }
            return true;
        }
        if (closed_) return true;
        std::vector<uint8_t> queued(*hdr_len + payload.size());
        std::memcpy(queued.data(), header_span.data(), header_span.size());
        if (!payload.empty()) {
            std::memcpy(queued.data() + *hdr_len, payload.data(), payload.size());
        }
        core_->datagrams.push_back(std::move(queued));
        Flush();
        return true;
    }
    try {
        for (size_t index = 0; index < fragments; ++index) {
            const size_t offset = index * fragment_payload;
            message.fragment_id = static_cast<uint8_t>(index);
            message.payload = payload.subspan(
                offset, std::min(fragment_payload, payload.size() - offset));
            auto encoded = EncodeUdpFragment(version, message, *text, *header_size);
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

void HysteriaConnection::CloseUdpSession(uint32_t session_id) noexcept {
    if (core_) {
        core_->udp_sessions.erase(session_id);
        common::MaybeShrinkHashContainer(core_->udp_sessions, 8);
    }
}

HysteriaIngress::HysteriaIngress(
    uint32_t worker_id_value, uint32_t worker_count_value, net::io_context& io_value,
    app::DatagramSessionEnvironment environment_value)
    : environment(std::move(environment_value)),
      worker_id(worker_id_value), worker_count(worker_count_value), io(io_value),
      changed(io, std::chrono::steady_clock::time_point::max()) {
    if (!environment.admission || !environment.prepared || !environment.handler ||
        !environment.dispatcher || !environment.request_load ||
        worker_count == 0 || worker_id >= worker_count)
        throw std::invalid_argument("incomplete Hysteria listener environment");
    const auto* settings = GetSettings(*environment.prepared);
    if (!settings) throw std::invalid_argument("missing Hysteria settings");
    version = settings->version;
    upload_bytes_per_second = settings->upload_bytes_per_second;
    download_bytes_per_second = settings->download_bytes_per_second;
    const auto& stream_settings = Receiver().stream_settings;
    const std::vector<std::string> default_alpn{
        version == HysteriaVersion::V2 ? "h3" : "hysteria"};
    const auto& alpn = version == HysteriaVersion::V2 || stream_settings.tls.alpn.empty()
        ? default_alpn : stream_settings.tls.alpn;
    if (!stream_settings.IsTls())
        throw std::invalid_argument("Hysteria requires TLS");
    ssl_context = SslContext::CreateQuicServer(stream_settings.tls, alpn);
    if (!ssl_context ||
        ngtcp2_crypto_boringssl_configure_server_context(ssl_context->Native()) != 0)
        throw std::invalid_argument("invalid Hysteria TLS settings");
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

bool HysteriaIngress::Queue(HysteriaSocketState& socket, std::span<const uint8_t> data,
                            const udp::endpoint& remote, HysteriaConnection& connection,
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
        std::vector<uint8_t>(data.begin(), data.end()),
        remote, connection.shared_from_this(), terminal});
    (void)socket.changed.try_send(IoErrorCode{});
    return true;
}

void HysteriaIngress::Associate(
    const ngtcp2_cid& cid, std::shared_ptr<HysteriaConnection> connection) {
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
    common::MaybeShrinkHashContainer(connections);
}

void HysteriaIngress::DissociateAll(HysteriaConnection& connection) noexcept {
    for (const auto& id : connection.connection_ids_) {
        connections.erase(id);
    }
    connection.connection_ids_.clear();
    common::MaybeShrinkHashContainer(connections);
}

HysteriaSocketState* HysteriaIngress::Resolve(const udp::endpoint& local) noexcept {
    for (auto& [key, socket] : sockets) {
        (void)key;
        if (socket->local == local && socket->socket && socket->socket->is_open())
            return socket.get();
    }
    return nullptr;
}


net::awaitable<void> HysteriaIngress::ReceiveLoop(std::shared_ptr<HysteriaSocketState> socket) {
    return RunUdpReceiveLoop(socket->socket,
        [this, socket](const std::shared_ptr<udp::socket>& current) noexcept {
            return !stopping && socket->socket == current && current && current->is_open();
        },
        [this, socket](const udp::endpoint& remote, std::span<const uint8_t> packet) {
            ProcessPacket(*socket, remote, packet);
        },
        [this]() noexcept { environment.admission->stats.OnError(); });
}

void HysteriaIngress::ProcessPacket(
    HysteriaSocketState& socket, const udp::endpoint& remote, std::span<const uint8_t> packet) {
    if (packet.empty()) return;
    ngtcp2_version_cid version_cid{};
    if (ngtcp2_pkt_decode_version_cid(&version_cid, packet.data(), packet.size(),
                                     kServerConnectionIdLength) != 0 ||
        version_cid.dcidlen > NGTCP2_MAX_CIDLEN) return;
    const ConnectionId cid(version_cid.dcid, version_cid.dcidlen);
    auto found = connections.find(cid);
    auto connection = found == connections.end() ? nullptr : found->second;
    if (!connection) {
        if ((packet[0] & 0x80) == 0) return;
        if (connections.size() >= kMaxConnections) {
            LOG_DEBUG("Hysteria listener connection capacity reached worker={}", worker_id);
            return;
        }
        ngtcp2_pkt_hd header{};
        if (ngtcp2_accept(&header, packet.data(), packet.size()) != 0) return;
        connection = HysteriaConnection::Create(*this, socket, remote, header);
        if (!connection) return;
    }
    if (connection->core_ && connection->core_->quic && !connection->Closed())
        connection->Feed(socket, remote, packet);
}

net::awaitable<void> HysteriaIngress::SendLoop(std::shared_ptr<HysteriaSocketState> socket) {
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


HysteriaIngress::SocketPtr HysteriaIngress::MakeSocket() {
    return std::make_shared<udp::socket>(io);
}

HysteriaIngress::SocketPtr HysteriaIngress::AttachSocket(
    std::string_view socket_key, SocketPtr socket) {
    if (!socket || !socket->is_open() || started || stopping)
        return {};
    (void)AttachQuicReuseportBpf(socket->native_handle(), worker_count);
    auto state = std::make_shared<HysteriaSocketState>(io);
    state->socket = std::move(socket);
    IoErrorCode error;
    state->local = state->socket->local_endpoint(error);
    if (error) return {};
    state->socket->non_blocking(true, error);
    if (error) return {};
    auto [it, inserted] = sockets.try_emplace(
        std::string(socket_key), state);
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
    std::weak_ptr<HysteriaConnection> owner)
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
    if (!input_.AppendSpan(data)) return false;
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
            throw transport::LinkError(common::ErrorCode::CANCELLED);
        if (input_done_) co_return 0;
        auto [error] = co_await input_signal_.async_receive(
            net::as_tuple(net::use_awaitable));
        if (error == net::experimental::error::channel_cancelled)
            error = net::error::operation_aborted;
        if (error)
            throw IoSystemError(error, "QUIC stream input cancelled");
    }
}

net::awaitable<common::MultiBuffer> QuicStreamState::ReadMultiBuffer() {
    for (;;) {
        if (!input_.empty()) {
            const size_t bytes = input_.byte_size();
            auto result = std::move(input_);
            input_.ReleaseIfIdle();
            AcknowledgeInput(bytes);
            co_return result;
        }
        if (cancelled_)
            throw transport::LinkError(common::ErrorCode::CANCELLED);
        if (input_done_) co_return common::MultiBuffer{};
        auto [error] = co_await input_signal_.async_receive(
            net::as_tuple(net::use_awaitable));
        if (error == net::experimental::error::channel_cancelled)
            error = net::error::operation_aborted;
        if (error)
            throw IoSystemError(error, "QUIC stream input cancelled");
    }
}

net::awaitable<void> QuicStreamState::WriteMultiBuffer(common::MultiBuffer payload) {
    CheckWriteOpen();
    auto owner = owner_.lock();
    if (!owner) {
        payload.clear();
        throw transport::LinkError(common::ErrorCode::CONNECTION_CLOSED);
    }
    // Only the stable state survives suspension, never a map iterator or
    // this object. ACKs release retained buffers; packet transmission alone
    // does not.
    const int64_t stream_id = stream_id_;
    while (auto state = owner->QueueStreamOutput(stream_id, payload))
        co_await state->WaitWritable();
}

void QuicStreamState::ShutdownWrite() noexcept {
    if (write_done_) return;
    write_done_ = true;
    NotifyWritable();
    if (auto owner = owner_.lock()) owner->ShutdownStreamWrite(stream_id_);
}

void QuicStreamState::CheckWriteOpen() const {
    if (cancelled_) throw transport::LinkError(common::ErrorCode::CANCELLED);
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
    if (!closed_) return state_->Read(buffer);
    return []() -> net::awaitable<size_t> { co_return 0; }();
}

net::awaitable<size_t> QuicStream::AsyncWrite(net::const_buffer buffer) {
    if (closed_) throw transport::LinkError(common::ErrorCode::CONNECTION_CLOSED);
    common::MultiBuffer payload;
    const auto bytes = std::span(
        static_cast<const uint8_t*>(buffer.data()), buffer.size());
    if (!payload.AppendSpan(bytes)) throw std::bad_alloc();
    co_await state_->WriteMultiBuffer(std::move(payload));
    co_return buffer.size();
}

net::awaitable<common::MultiBuffer> QuicStream::ReadMultiBuffer() {
    if (!closed_) return state_->ReadMultiBuffer();
    return []() -> net::awaitable<common::MultiBuffer> { co_return common::MultiBuffer{}; }();
}

net::awaitable<void> QuicStream::WriteMultiBuffer(common::MultiBuffer payload) {
    if (!closed_) return state_->WriteMultiBuffer(std::move(payload));
    return [](common::MultiBuffer rejected) -> net::awaitable<void> {
        rejected.clear();
        throw transport::LinkError(common::ErrorCode::CONNECTION_CLOSED);
        co_return;
    }(std::move(payload));
}

net::awaitable<void> QuicStream::WriteBuffers(
    std::span<const net::const_buffer> buffers) {
    if (closed_) return WriteMultiBuffer({});
    common::MultiBuffer payload;
    for (const auto& buffer : buffers) {
        const auto bytes = std::span(
            static_cast<const uint8_t*>(buffer.data()), buffer.size());
        if (!payload.AppendSpan(bytes)) {
            return [](common::MultiBuffer) -> net::awaitable<void> {
                throw std::bad_alloc();
                co_return;
            }(std::move(payload));
        }
    }
    return state_->WriteMultiBuffer(std::move(payload));
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
    std::weak_ptr<HysteriaConnection> owner)
    : session_id_(session_id)
    , owner_(std::move(owner))
    , signal_(io_context.get_executor(), 1)
    , deadline_(io_context, *this) {}

UdpSessionStream::~UdpSessionStream() noexcept {
    Close();
}

bool UdpSessionStream::Push(
    const common::TargetAddress& target, std::span<const uint8_t> payload) {
    if (!CanAcceptBytes(payload.size())) return false;
    common::MultiBuffer packet;
    if (!packet.AppendSpan(payload)) return false;
    return PushMultiBuffer(target, std::move(packet));
}

void UdpSessionStream::Detach() noexcept {
    owner_.reset();
    Close();
}

net::awaitable<size_t> UdpSessionStream::AsyncRead(net::mutable_buffer) {
    throw transport::LinkError(common::ErrorCode::NOT_SUPPORTED);
}

net::awaitable<size_t> UdpSessionStream::AsyncWrite(net::const_buffer) {
    throw transport::LinkError(common::ErrorCode::NOT_SUPPORTED);
}

net::awaitable<common::MultiBuffer> UdpSessionStream::ReadMultiBuffer() {
    for (;;) {
        if (cancelled_) throw transport::LinkError(common::ErrorCode::CANCELLED);
        if (!input_.empty()) {
            auto packet = std::move(input_.front());
            input_.pop_front();
            const size_t packet_blocks =
                packet.byte_size() == 0 ? 1 : 1 + (packet.byte_size() - 1) / common::Buffer::kSize;
            queued_buffer_count_ -= packet_blocks;
            co_return packet;
        }
        if (closed_) co_return common::MultiBuffer{};
        auto [error] = co_await signal_.async_receive(
            net::as_tuple(net::use_awaitable));
        if (error == net::experimental::error::channel_cancelled)
            error = net::error::operation_aborted;
        if (error)
            throw IoSystemError(error, "Hysteria UDP session input cancelled");
    }
}

net::awaitable<void> UdpSessionStream::WriteMultiBuffer(common::MultiBuffer packet) {
    const auto datagram = common::InspectUdpDatagram(packet);
    if (datagram.status == common::UdpDatagramStatus::Empty) co_return;
    if (!datagram.Valid() || datagram.payload_size > kMaxUdpPayloadLength) {
        packet.clear();
        throw transport::LinkError(common::ErrorCode::PROTOCOL_INVALID_ADDRESS);
    }
    auto owner = owner_.lock();
    if (closed_ || !owner) {
        packet.clear();
        throw transport::LinkError(common::ErrorCode::CONNECTION_CLOSED);
    }
    const bool sent = owner->SendUdpMessage(
        session_id_, *datagram.target, datagram.single_buffer->Bytes());
    packet.clear();
    if (!sent) throw transport::LinkError(common::ErrorCode::RESOURCE_EXHAUSTED);
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


}  // namespace transport
