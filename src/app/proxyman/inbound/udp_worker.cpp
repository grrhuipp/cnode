#include "acppnode/app/proxyman/inbound/udp_worker.hpp"

#include "acppnode/app/proxyman/inbound/receiver_settings.hpp"
#include "acppnode/common/initial_payload.hpp"
#include "acppnode/common/ip_utils.hpp"
#include "acppnode/common/session.hpp"
#include "acppnode/common/allocator.hpp"
#include "acppnode/common/container_util.hpp"
#include "acppnode/features/routing/dispatcher.hpp"
#include "acppnode/infra/config_types.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/transport/async_stream.hpp"

#include <asio/as_tuple.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/experimental/channel.hpp>
#include <asio/use_awaitable.hpp>

#include <unordered_map>

namespace acpp::proxyman::inbound {

class UdpWorker::PendingUdpReply {
public:
    udp::endpoint endpoint;
    buf::MultiBuffer payload;
    size_t payload_size = 0;
    std::array<net::const_buffer, buf::MultiBuffer::kInlineCapacity> inline_send_buffers{};
    memory::ThreadLocalVector<net::const_buffer> spill_send_buffers;
    size_t send_buffer_count = 0;

    [[nodiscard]] size_t PayloadSize() const noexcept {
        return payload_size;
    }

    void PrepareSendBuffers() {
        spill_send_buffers.clear();
        send_buffer_count = 0;
        for (const auto* buffer : payload) {
            if (buffer && !buffer->IsEmpty()) {
                const auto bytes = buffer->Bytes();
                net::const_buffer send_buffer{bytes.data(), bytes.size()};
                if (send_buffer_count < inline_send_buffers.size()) {
                    inline_send_buffers[send_buffer_count++] = send_buffer;
                    continue;
                }
                if (spill_send_buffers.empty()) {
                    spill_send_buffers.reserve(payload.size());
                    spill_send_buffers.insert(
                        spill_send_buffers.end(),
                        inline_send_buffers.begin(),
                        inline_send_buffers.begin() + send_buffer_count);
                }
                spill_send_buffers.emplace_back(send_buffer);
                ++send_buffer_count;
            }
        }
    }

    [[nodiscard]] std::span<const net::const_buffer> SendBuffers() const noexcept {
        if (!spill_send_buffers.empty()) {
            return std::span<const net::const_buffer>(
                spill_send_buffers.data(),
                spill_send_buffers.size());
        }
        return std::span<const net::const_buffer>(
            inline_send_buffers.data(),
            send_buffer_count);
    }
};

namespace {

constexpr size_t kMaxQueuedUdpDatagrams = 256;
constexpr size_t kMaxQueuedUdpBytes = 512 * 1024;

[[nodiscard]] bool WouldOverflowUdpQueue(
    size_t queued_datagrams,
    size_t queued_bytes,
    size_t payload_size) noexcept {
    return queued_datagrams >= kMaxQueuedUdpDatagrams ||
        payload_size > kMaxQueuedUdpBytes ||
        queued_bytes > kMaxQueuedUdpBytes - payload_size;
}

struct UdpReplyQueueState {
    memory::ThreadLocalDeque<UdpWorker::PendingUdpReply> pending;
    size_t queued_bytes = 0;
    bool write_in_progress = false;
    bool shrink_pending_on_drain = false;
};

struct UdpClientSession {
    UdpWorker::ClientSessionPtr link;
    std::chrono::steady_clock::time_point last_active;
};

using UdpClientSessionMap =
    std::unordered_map<
        std::string,
        UdpClientSession>;

}  // namespace

struct UdpWorker::ClientSession::Impl {
    Impl(net::io_context& io_context,
         ReplyCallback reply_callback,
         udp::endpoint reply_endpoint,
         UdpSessionOwner session_owner)
        : io_context(io_context)
        , reader_signal(io_context, 1)
        , reply_callback(std::move(reply_callback))
        , reply_endpoint(std::move(reply_endpoint))
        , session_owner(std::move(session_owner)) {}

    void WakeReader() {
        (void)reader_signal.try_send(IoErrorCode{});
    }

    net::io_context& io_context;
    net::experimental::channel<void(IoErrorCode)> reader_signal;
    ReplyCallback reply_callback;
    udp::endpoint reply_endpoint;
    struct QueuedInput {
        buf::MultiBuffer payload;
        size_t bytes = 0;
    };
    memory::ThreadLocalDeque<QueuedInput> input_queue;
    size_t queued_bytes = 0;
    bool shrink_queue_on_drain = false;
    bool closed = false;
    UdpSessionOwner session_owner;
};

UdpWorker::ClientSession::ClientSession(
    net::io_context& io_context,
    ReplyCallback reply_callback,
    udp::endpoint reply_endpoint,
    UdpSessionOwner session_owner)
    : impl_(std::make_unique<Impl>(
          io_context,
          std::move(reply_callback),
          std::move(reply_endpoint),
          std::move(session_owner))) {}

UdpWorker::ClientSession::~ClientSession() noexcept {
    Close();
}

bool UdpWorker::ClientSession::Closed() const noexcept {
    return impl_->closed;
}

bool UdpWorker::ClientSession::Owns(
    const UdpSessionOwner& owner) const noexcept {
    return impl_->session_owner.Same(owner);
}

void UdpWorker::ClientSession::UpdateReplyEndpoint(
    udp::endpoint endpoint) noexcept {
    impl_->reply_endpoint = std::move(endpoint);
}

bool UdpWorker::ClientSession::Push(
    const TargetAddress& target,
    buf::MultiBuffer payload) {
    const size_t payload_size = buf::TotalLen(payload);
    if (impl_->closed || payload_size == 0) {
        payload.clear();
        return false;
    }
    if (WouldOverflowUdpQueue(
            impl_->input_queue.size(), impl_->queued_bytes, payload_size)) {
        payload.clear();
        return false;
    }

    for (buf::Buffer* buffer : payload) {
        if (buffer && !buffer->IsEmpty()) {
            buffer->SetUDP(target);
        }
    }

    impl_->queued_bytes += payload_size;
    impl_->input_queue.push_back(Impl::QueuedInput{std::move(payload), payload_size});
    if (impl_->input_queue.size() >= 64 || impl_->queued_bytes >= 256 * 1024) {
        impl_->shrink_queue_on_drain = true;
    }
    impl_->WakeReader();
    return true;
}

void UdpWorker::ClientSession::Close() noexcept {
    if (impl_->closed) {
        return;
    }
    impl_->closed = true;
    impl_->input_queue.clear();
    impl_->queued_bytes = 0;
    impl_->WakeReader();
}

net::awaitable<buf::MultiBuffer>
UdpWorker::ClientSession::ReadMultiBuffer() {
    while (true) {
        if (!impl_->input_queue.empty()) {
            auto input = std::move(impl_->input_queue.front());
            impl_->queued_bytes -= std::min(impl_->queued_bytes, input.bytes);
            impl_->input_queue.pop_front();
            if (impl_->input_queue.empty() && impl_->shrink_queue_on_drain) {
                TryShrinkSequence(impl_->input_queue);
                impl_->shrink_queue_on_drain = false;
            }
            co_return std::move(input.payload);
        }

        if (impl_->closed) {
            co_return buf::MultiBuffer{};
        }

        auto [ec] = co_await impl_->reader_signal.async_receive(
            net::as_tuple(net::use_awaitable));
        (void)ec;
    }
}

net::awaitable<void>
UdpWorker::ClientSession::WriteMultiBuffer(buf::MultiBuffer mb) {
    if (impl_->closed || !impl_->reply_callback) {
        mb.clear();
        co_return;
    }

    const auto datagram = buf::InspectUdpDatagram(mb);
    if (datagram.status == buf::UdpDatagramStatus::Empty) {
        mb.clear();
        co_return;
    }
    if (!datagram.Valid()) {
        mb.clear();
        throw IoSystemError(
            io_error::invalid_argument,
            "UDP client reply contains missing or mixed endpoints");
    }

    std::span<const uint8_t> payload;
    memory::ByteVector coalesced;
    if (datagram.buffer_count == 1) {
        payload = datagram.single_buffer->Bytes();
    } else {
        coalesced.reserve(datagram.payload_size);
        for (const buf::Buffer* buffer : mb) {
            if (!buffer || buffer->IsEmpty()) {
                continue;
            }
            const auto bytes = buffer->Bytes();
            coalesced.insert(coalesced.end(), bytes.begin(), bytes.end());
        }
        payload = coalesced;
    }

    if (!impl_->reply_callback(
            UDPPacketView{*datagram.target, payload},
            impl_->reply_endpoint)) {
        mb.clear();
        throw IoSystemError(
            io_error::fault, "UDP client reply callback failed");
    }
    mb.clear();
    co_return;
}

net::awaitable<void>
UdpWorker::ClientSession::WriteBuffers(std::span<const net::const_buffer>) {
    co_return;
}

struct UdpWorker::Impl {
    using UdpSocketMap =
        memory::ThreadLocalUnorderedMap<std::string, UdpWorker::SocketPtr>;

    Impl(std::string tag, std::unique_ptr<UdpHandler> proxy)
        : tag(std::move(tag))
        , proxy(std::move(proxy)) {}

    std::string tag;
    std::unique_ptr<UdpHandler> proxy;
    UdpSocketMap udp_sockets;
    memory::ThreadLocalUnorderedMap<std::string, UdpReplyQueueState> reply_queues;
    memory::ThreadLocalUnorderedMap<std::string, UdpClientSessionMap> client_sessions;
};

UdpWorker::UdpWorker(std::string tag, std::unique_ptr<UdpHandler> proxy)
    : impl_(std::make_unique<Impl>(std::move(tag), std::move(proxy))) {}

UdpWorker::~UdpWorker() noexcept = default;
UdpWorker::UdpWorker(UdpWorker&&) noexcept = default;
UdpWorker& UdpWorker::operator=(UdpWorker&&) noexcept = default;

void UdpWorker::PendingUdpReplyDeleter::operator()(
    PendingUdpReply* reply) const noexcept {
    delete reply;
}

std::string_view UdpWorker::Tag() const noexcept {
    return impl_->tag;
}

bool UdpWorker::ReplaceHandler(std::unique_ptr<UdpHandler> proxy) noexcept {
    if (!proxy) {
        return false;
    }
    if (impl_->proxy) {
        proxy->AdoptWorkerStateFrom(*impl_->proxy);
    }
    impl_->proxy = std::move(proxy);
    return true;
}

void UdpWorker::Close() noexcept {
    CloseAllSockets();
    CleanupAllClientSessions();
    impl_->reply_queues.clear();
    MaybeShrinkHashContainer(impl_->reply_queues, 8);
}

void UdpWorker::ProcessDatagram(const UdpDatagramContext& datagram) {
    if (!impl_->proxy || !datagram.sock || datagram.payload.empty()) {
        return;
    }

    const std::string socket_key(datagram.socket_key);
    const auto now = std::chrono::steady_clock::now();

    const std::string client_ip =
        iputil::NormalizeAddressString(datagram.client_endpoint.address());
    const auto normalized_client_addr =
        iputil::NormalizeAddress(datagram.client_endpoint.address());
    auto decoded = impl_->proxy->DecodeUdp(
        impl_->tag, client_ip, datagram.payload.data(), datagram.payload.size());
    if (!decoded) {
        return;
    }

    auto client_key_log = [&]() {
        return iputil::FormatEndpointForLog(client_ip, datagram.client_endpoint.port());
    };
    std::string protocol_session_key;
    if (!decoded->session_key.empty()) {
        protocol_session_key = decoded->session_key;
    } else {
        protocol_session_key = client_key_log();
    }
    std::string client_session_key =
        decoded->session_owner.ScopeSessionKey(protocol_session_key);
    if (client_session_key.empty()) {
        LOG_ACCESS_DEBUG(
            "Worker[{}]: UDP decode missing authenticated session owner for client={}",
            datagram.worker_id,
            client_key_log());
        return;
    }

    const bool need_new_session = !HasClientSession(socket_key, client_session_key);

    if (need_new_session) {
        if (!decoded->response_context) {
            LOG_ACCESS_DEBUG("Worker[{}]: UDP decode missing response context for client={}",
                             datagram.worker_id, client_key_log());
            return;
        }

        auto receiver = std::make_shared<ReceiverSettings>();
        if (datagram.receiver) {
            *receiver = *datagram.receiver;
        } else {
            receiver->inbound_tag = impl_->tag;
            receiver->inbound_tags = {impl_->tag};
        }

        auto ctx = std::make_shared<session::Context>();
        ctx->conn_id = session::NewID(datagram.worker_id);
        ctx->worker_id = datagram.worker_id;
        ctx->inbound.tag = receiver->inbound_tag.empty()
            ? std::string_view(impl_->tag)
            : std::string_view(receiver->inbound_tag);
        ctx->inbound.tags = receiver->RouteInboundTags();
        ctx->inbound.source_ip = client_ip;
        ctx->inbound.source_addr = normalized_client_addr;
        ctx->inbound.source_port = datagram.client_endpoint.port();
        IoErrorCode local_ec;
        const auto local_ep = datagram.sock->local_endpoint(local_ec);
        if (!local_ec && !local_ep.address().is_unspecified()) {
            const auto local_addr = iputil::NormalizeAddress(local_ep.address());
            ctx->inbound.local_endpoint = tcp::endpoint(local_addr, local_ep.port());
        }
        ctx->content.network = Network::UDP;
        ctx->outbound.original_target = decoded->target;
        ctx->outbound.target = decoded->target;
        ctx->inbound.user_id = decoded->user_id;
        ctx->inbound.user_email = decoded->user_email;
        ctx->inbound.access_source_ref = receiver->access_source_ref;
        ctx->inbound.protocol = receiver->protocol;
        ctx->content.speed_limit = decoded->speed_limit;

        auto response_context = std::move(decoded->response_context);
        udp::socket* sock = datagram.sock;
        auto& reply_sink = datagram.reply_sink;
        const uint32_t worker_id = datagram.worker_id;

        auto reply_cb = [socket_key,
                         sock,
                         response_context = std::move(response_context),
                         &reply_sink,
                         worker_id](UDPPacketView pkt,
                                    const udp::endpoint& reply_endpoint) mutable {
            auto payload = response_context->Encode(pkt);
            if (payload.empty()) {
                return;
            }
            reply_sink.EnqueueUdpReply(
                socket_key,
                sock,
                reply_endpoint,
                std::move(payload),
                worker_id);
        };

        auto client_session = CreateClientSession(
            socket_key,
            client_session_key,
            datagram.io_context,
            std::move(reply_cb),
            datagram.client_endpoint,
            decoded->session_owner,
            now);

        auto* dispatcher = &datagram.dispatcher;
        auto* io_context = &datagram.io_context;
        auto* stats = &datagram.stats;
        auto timeouts = datagram.timeouts;
        net::co_spawn(
            io_context->get_executor(),
            [dispatcher,
             io_context,
             stats,
             receiver,
             ctx,
             client_session,
             timeouts,
             worker_id]() -> net::awaitable<void> {
                try {
                    RelayResult relay_result = co_await dispatcher->Dispatch(
                        *io_context,
                        *receiver,
                        nullptr,
                        transport::Link{client_session.get(), client_session.get()},
                        InitialPayload{},
                        *ctx,
                        *stats,
                        timeouts);
                    if (relay_result.error != ErrorCode::OK) {
                        auto& log_ctx = *ctx;
                        LOG_CONN_DEBUG(log_ctx, "[UDP] dispatcher session end: {} up={}B down={}B",
                                       ErrorCodeToString(relay_result.error),
                                       relay_result.bytes_up,
                                       relay_result.bytes_down);
                    }
                } catch (const std::exception& e) {
                    LOG_ERROR("Worker[{}]: UDP dispatcher coroutine failed: {}",
                              worker_id, e.what());
                } catch (...) {
                    LOG_ERROR("Worker[{}]: UDP dispatcher coroutine failed: unknown",
                              worker_id);
                }
                client_session->Close();
                co_return;
            },
            net::detached);
    }

    if (!PushClientPayload(
        socket_key,
        client_session_key,
        decoded->target,
        datagram.client_endpoint,
        decoded->session_owner,
        std::move(decoded->payload),
        now)) {
        LOG_ACCESS_DEBUG("Worker[{}]: UDP link enqueue failed for client={}",
                         datagram.worker_id, client_key_log());
    }
}

bool UdpWorker::EnqueueReply(const std::string& socket_key,
                             udp::endpoint endpoint,
                             buf::MultiBuffer payload) {
    const size_t payload_size = buf::TotalLen(payload);
    if (payload_size == 0) {
        return false;
    }

    auto& queue = impl_->reply_queues[socket_key];
    if (WouldOverflowUdpQueue(
            queue.pending.size(), queue.queued_bytes, payload_size)) {
        return false;
    }
    const bool should_start_send = !queue.write_in_progress;
    queue.queued_bytes += payload_size;

    PendingUdpReply reply;
    reply.endpoint = std::move(endpoint);
    reply.payload_size = payload_size;
    reply.payload = std::move(payload);
    queue.pending.push_back(std::move(reply));
    if (queue.pending.size() >= 64 || queue.queued_bytes >= 256 * 1024) {
        queue.shrink_pending_on_drain = true;
    }
    return should_start_send;
}

bool UdpWorker::EnqueueReply(const std::string& socket_key,
                             udp::endpoint endpoint,
                             buf::BufferGuard payload) {
    if (!payload || payload->IsEmpty()) {
        return false;
    }

    const size_t payload_size = payload->Len();
    auto& queue = impl_->reply_queues[socket_key];
    if (WouldOverflowUdpQueue(
            queue.pending.size(), queue.queued_bytes, payload_size)) {
        return false;
    }
    const bool should_start_send = !queue.write_in_progress;
    queue.queued_bytes += payload_size;

    PendingUdpReply reply;
    reply.endpoint = std::move(endpoint);
    reply.payload_size = payload_size;
    reply.payload.push_back(payload.release());
    queue.pending.push_back(std::move(reply));
    if (queue.pending.size() >= 64 || queue.queued_bytes >= 256 * 1024) {
        queue.shrink_pending_on_drain = true;
    }
    return should_start_send;
}

UdpWorker::PendingUdpReplyPtr
UdpWorker::BeginReplySend(const std::string& socket_key) {
    auto it = impl_->reply_queues.find(socket_key);
    if (it == impl_->reply_queues.end()) {
        return nullptr;
    }

    auto& queue = it->second;
    if (queue.write_in_progress || queue.pending.empty()) {
        return nullptr;
    }

    PendingUdpReplyPtr packet{
        new PendingUdpReply(std::move(queue.pending.front()))};
    queue.queued_bytes -= packet->PayloadSize();
    queue.pending.pop_front();
    queue.write_in_progress = true;
    packet->PrepareSendBuffers();
    return packet;
}

std::span<const net::const_buffer>
UdpWorker::ReplySendBuffers(const PendingUdpReply& reply) noexcept {
    return reply.SendBuffers();
}

const udp::endpoint&
UdpWorker::ReplyEndpoint(const PendingUdpReply& reply) noexcept {
    return reply.endpoint;
}

bool UdpWorker::CompleteReplySend(const std::string& socket_key) {
    auto it = impl_->reply_queues.find(socket_key);
    if (it == impl_->reply_queues.end()) {
        return false;
    }

    auto& queue = it->second;
    queue.write_in_progress = false;
    if (queue.pending.empty()) {
        if (queue.shrink_pending_on_drain) {
            TryShrinkSequence(queue.pending);
            queue.shrink_pending_on_drain = false;
        }
        return false;
    }
    return true;
}

void UdpWorker::ClearReplyQueue(const std::string& socket_key) {
    impl_->reply_queues.erase(socket_key);
    MaybeShrinkHashContainer(impl_->reply_queues, 8);
}

bool UdpWorker::HasClientSession(const std::string& socket_key,
                                 const std::string& client_key) const noexcept {
    auto session = FindClientSession(socket_key, client_key);
    return session && !session->Closed();
}

UdpWorker::ClientSessionPtr UdpWorker::FindClientSession(
    const std::string& socket_key,
    const std::string& client_key) const noexcept {
    auto sessions_it = impl_->client_sessions.find(socket_key);
    if (sessions_it == impl_->client_sessions.end()) {
        return nullptr;
    }
    auto session_it = sessions_it->second.find(client_key);
    if (session_it == sessions_it->second.end()) {
        return nullptr;
    }
    return session_it->second.link;
}

UdpWorker::ClientSessionPtr UdpWorker::CreateClientSession(
    const std::string& socket_key,
    const std::string& client_key,
    net::io_context& io_context,
    ReplyCallback reply_callback,
    udp::endpoint reply_endpoint,
    UdpSessionOwner session_owner,
    std::chrono::steady_clock::time_point now) {
    auto session = std::make_shared<ClientSession>(
        io_context,
        std::move(reply_callback),
        std::move(reply_endpoint),
        std::move(session_owner));
    auto& sessions = impl_->client_sessions[socket_key];
    sessions.insert_or_assign(client_key, UdpClientSession{
        .link = session,
        .last_active = now,
    });
    return session;
}

bool UdpWorker::PushClientPayload(
    const std::string& socket_key,
    const std::string& client_key,
    const TargetAddress& target,
    udp::endpoint reply_endpoint,
    const UdpSessionOwner& session_owner,
    buf::MultiBuffer payload,
    std::chrono::steady_clock::time_point now) {
    auto sessions_it = impl_->client_sessions.find(socket_key);
    if (sessions_it == impl_->client_sessions.end()) {
        payload.clear();
        return false;
    }
    auto session_it = sessions_it->second.find(client_key);
    if (session_it == sessions_it->second.end() ||
        !session_it->second.link ||
        session_it->second.link->Closed() ||
        !session_it->second.link->Owns(session_owner)) {
        payload.clear();
        return false;
    }

    auto& session = session_it->second;
    session.last_active = now;
    session.link->UpdateReplyEndpoint(std::move(reply_endpoint));
    return session.link->Push(target, std::move(payload));
}

void UdpWorker::CleanupIdleClientSessions(
    const std::string& socket_key,
    std::chrono::steady_clock::time_point now,
    std::chrono::seconds idle_timeout) {
    if (idle_timeout.count() <= 0) {
        return;
    }

    auto sessions_it = impl_->client_sessions.find(socket_key);
    if (sessions_it == impl_->client_sessions.end()) {
        return;
    }

    bool removed_idle_session = false;
    for (auto it = sessions_it->second.begin(); it != sessions_it->second.end();) {
        if (now - it->second.last_active > idle_timeout) {
            if (it->second.link) {
                it->second.link->Close();
            }
            it = sessions_it->second.erase(it);
            removed_idle_session = true;
        } else {
            ++it;
        }
    }
    if (removed_idle_session) {
        MaybeShrinkHashContainer(sessions_it->second, 64);
    }
}

void UdpWorker::CleanupClientSessions(const std::string& socket_key) noexcept {
    auto sessions_it = impl_->client_sessions.find(socket_key);
    if (sessions_it == impl_->client_sessions.end()) {
        return;
    }

    for (auto& [client_key, session] : sessions_it->second) {
        (void)client_key;
        if (session.link) {
            session.link->Close();
        }
    }

    impl_->client_sessions.erase(sessions_it);
    MaybeShrinkHashContainer(impl_->client_sessions, 8);
}

void UdpWorker::CleanupAllClientSessions() noexcept {
    while (!impl_->client_sessions.empty()) {
        CleanupClientSessions(impl_->client_sessions.begin()->first);
    }
}

udp::socket* UdpWorker::AttachSocket(
    const std::string& socket_key,
    SocketPtr socket) {
    if (!socket) {
        return nullptr;
    }
    auto [it, inserted] = impl_->udp_sockets.try_emplace(
        socket_key, std::move(socket));
    return inserted ? it->second.get() : nullptr;
}

udp::socket* UdpWorker::FindSocket(const std::string& socket_key) noexcept {
    auto it = impl_->udp_sockets.find(socket_key);
    return it == impl_->udp_sockets.end() ? nullptr : it->second.get();
}

const udp::socket* UdpWorker::FindSocket(const std::string& socket_key) const noexcept {
    auto it = impl_->udp_sockets.find(socket_key);
    return it == impl_->udp_sockets.end() ? nullptr : it->second.get();
}

std::vector<std::string> UdpWorker::SocketKeys() const {
    std::vector<std::string> keys;
    keys.reserve(impl_->udp_sockets.size());
    for (const auto& [socket_key, socket] : impl_->udp_sockets) {
        (void)socket;
        keys.push_back(socket_key);
    }
    return keys;
}

void UdpWorker::CloseSocket(const std::string& socket_key) noexcept {
    CleanupClientSessions(socket_key);
    ClearReplyQueue(socket_key);

    auto sock_it = impl_->udp_sockets.find(socket_key);
    if (sock_it == impl_->udp_sockets.end()) {
        return;
    }

    IoErrorCode ec;
    sock_it->second->cancel(ec);
    sock_it->second->close(ec);
    impl_->udp_sockets.erase(sock_it);
    MaybeShrinkHashContainer(impl_->udp_sockets, 8);
}

void UdpWorker::CloseAllSockets() noexcept {
    while (!impl_->udp_sockets.empty()) {
        CloseSocket(impl_->udp_sockets.begin()->first);
    }
}

}  // namespace acpp::proxyman::inbound
