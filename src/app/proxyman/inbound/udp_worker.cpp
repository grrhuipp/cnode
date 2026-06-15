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

#include <asio/experimental/channel.hpp>

#include <deque>
#include <unordered_map>

namespace acpp::proxyman::inbound {

class UdpWorker::PendingUdpReply {
public:
    udp::endpoint endpoint;
    buf::MultiBuffer payload;
    std::vector<net::const_buffer> send_buffers;

    [[nodiscard]] size_t PayloadSize() const noexcept {
        return buf::TotalLen(payload);
    }

    void PrepareSendBuffers() {
        send_buffers.clear();
        send_buffers.reserve(payload.size());
        for (const auto* buffer : payload) {
            if (buffer && !buffer->IsEmpty()) {
                send_buffers.emplace_back(buffer->Bytes().data(), buffer->Len());
            }
        }
    }
};

namespace {

struct UdpReplyQueueState {
    std::deque<UdpWorker::PendingUdpReply> pending;
    size_t queued_bytes = 0;
    bool write_in_progress = false;
    bool shrink_pending_on_drain = false;
};

struct UdpClientSession {
    UdpWorker::ClientSessionPtr link;
    int64_t user_id = 0;
    std::chrono::steady_clock::time_point last_active;
};

using UdpClientSessionMap =
    std::unordered_map<
        UdpEndpointKey,
        UdpClientSession,
        UdpEndpointKeyHash>;

struct UdpSocketDeleter {
    void operator()(udp::socket* socket) const noexcept {
        if (!socket) {
            return;
        }
        std::destroy_at(socket);
        memory::ThreadLocalAllocator<udp::socket>{}.deallocate(socket, 1);
    }
};

using UdpSocketPtr = std::unique_ptr<udp::socket, UdpSocketDeleter>;

}  // namespace

struct UdpWorker::ClientSession::Impl {
    Impl(net::io_context& io_context,
         ReplyCallback reply_callback,
         int64_t user_id)
        : io_context(io_context)
        , reader_signal(io_context, 1)
        , reply_callback(std::move(reply_callback))
        , user_id(user_id) {}

    void WakeReader() {
        (void)reader_signal.try_send(IoErrorCode{});
    }

    net::io_context& io_context;
    net::experimental::channel<void(IoErrorCode)> reader_signal;
    ReplyCallback reply_callback;
    std::deque<buf::MultiBuffer> input_queue;
    size_t queued_bytes = 0;
    bool shrink_queue_on_drain = false;
    bool closed = false;
    int64_t user_id = 0;
};

UdpWorker::ClientSession::ClientSession(
    net::io_context& io_context,
    ReplyCallback reply_callback,
    int64_t user_id)
    : impl_(std::make_unique<Impl>(
          io_context, std::move(reply_callback), user_id)) {}

UdpWorker::ClientSession::~ClientSession() noexcept {
    Close();
}

int64_t UdpWorker::ClientSession::UserId() const noexcept {
    return impl_->user_id;
}

bool UdpWorker::ClientSession::Closed() const noexcept {
    return impl_->closed;
}

void UdpWorker::ClientSession::Push(
    const TargetAddress& target,
    buf::MultiBuffer payload) {
    const size_t payload_size = buf::TotalLen(payload);
    if (impl_->closed || payload_size == 0) {
        payload.clear();
        return;
    }
    if (impl_->queued_bytes + payload_size > 512 * 1024) {
        payload.clear();
        return;
    }

    for (buf::Buffer* buffer : payload) {
        if (buffer && !buffer->IsEmpty()) {
            buffer->SetUDP(target);
        }
    }

    impl_->queued_bytes += payload_size;
    impl_->input_queue.push_back(std::move(payload));
    if (impl_->input_queue.size() >= 64 || impl_->queued_bytes >= 256 * 1024) {
        impl_->shrink_queue_on_drain = true;
    }
    impl_->WakeReader();
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
            buf::MultiBuffer mb = std::move(impl_->input_queue.front());
            impl_->queued_bytes -= std::min(
                impl_->queued_bytes, buf::TotalLen(mb));
            impl_->input_queue.pop_front();
            if (impl_->input_queue.empty() && impl_->shrink_queue_on_drain) {
                TryShrinkSequence(impl_->input_queue);
                impl_->shrink_queue_on_drain = false;
            }
            co_return mb;
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

    for (buf::Buffer* buffer : mb) {
        if (!buffer || buffer->IsEmpty() || !buffer->HasUDP()) {
            continue;
        }
        impl_->reply_callback(UDPPacketView{
            buffer->udp,
            buffer->Bytes(),
        });
    }
    mb.clear();
    co_return;
}

struct UdpWorker::Impl {
    using UdpSocketMap =
        memory::ThreadLocalUnorderedMap<std::string, UdpSocketPtr>;

    Impl(std::string tag, std::unique_ptr<UdpHandler> proxy)
        : tag(std::move(tag))
        , proxy(std::move(proxy)) {}

    std::string tag;
    std::unique_ptr<UdpHandler> proxy;
    UdpSocketMap udp_sockets;
    memory::ThreadLocalVector<UdpSocketPtr> retired_udp_sockets;
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

void UdpWorker::Close() noexcept {
    CloseAllSockets();
    CleanupAllClientSessions();
    impl_->reply_queues.clear();
    MaybeShrinkHashContainer(impl_->reply_queues, 8);
}

void UdpWorker::SetBanTrackingEnabled(bool enabled) noexcept {
    if (impl_->proxy) {
        impl_->proxy->SetBanTrackingEnabled(enabled);
    }
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

    const UdpEndpointKey client_key{
        normalized_client_addr,
        datagram.client_endpoint.port(),
    };
    auto client_key_log = [&]() {
        return iputil::FormatEndpointForLog(client_ip, datagram.client_endpoint.port());
    };

    const bool need_new_session = !HasClientSession(socket_key, client_key);

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
        ctx->content.speed_limit = decoded->speed_limit;

        auto response_context = decoded->response_context;
        udp::endpoint endpoint = datagram.client_endpoint;
        udp::socket* sock = datagram.sock;
        auto& reply_sink = datagram.reply_sink;
        const uint32_t worker_id = datagram.worker_id;

        auto reply_cb = [this,
                         socket_key,
                         sock,
                         endpoint,
                         response_context = std::move(response_context),
                         &reply_sink,
                         worker_id](UDPPacketView pkt) mutable {
            if (!impl_->proxy) {
                return;
            }
            auto payload = impl_->proxy->EncodeUdpResponse(pkt, *response_context);
            if (payload.empty()) {
                return;
            }
            reply_sink.EnqueueUdpReply(
                socket_key, sock, endpoint, std::move(payload), worker_id);
        };

        auto client_session = CreateClientSession(
            socket_key,
            client_key,
            datagram.io_context,
            std::move(reply_cb),
            decoded->user_id,
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
                        timeouts,
                        0);
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
        client_key,
        decoded->target,
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
    const bool should_start_send = !queue.write_in_progress;
    queue.queued_bytes += payload_size;

    PendingUdpReply reply;
    reply.endpoint = std::move(endpoint);
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
    const bool should_start_send = !queue.write_in_progress;
    queue.queued_bytes += payload_size;

    PendingUdpReply reply;
    reply.endpoint = std::move(endpoint);
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

const std::vector<net::const_buffer>&
UdpWorker::ReplySendBuffers(const PendingUdpReply& reply) noexcept {
    return reply.send_buffers;
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
                                 const UdpEndpointKey& client_key) const noexcept {
    auto session = FindClientSession(socket_key, client_key);
    return session && !session->Closed();
}

UdpWorker::ClientSessionPtr UdpWorker::FindClientSession(
    const std::string& socket_key,
    const UdpEndpointKey& client_key) const noexcept {
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
    const UdpEndpointKey& client_key,
    net::io_context& io_context,
    ReplyCallback reply_callback,
    int64_t user_id,
    std::chrono::steady_clock::time_point now) {
    auto session = std::make_shared<ClientSession>(
        io_context, std::move(reply_callback), user_id);
    auto& sessions = impl_->client_sessions[socket_key];
    sessions.insert_or_assign(client_key, UdpClientSession{
        .link = session,
        .user_id = user_id,
        .last_active = now,
    });
    return session;
}

bool UdpWorker::PushClientPayload(
    const std::string& socket_key,
    const UdpEndpointKey& client_key,
    const TargetAddress& target,
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
        session_it->second.link->Closed()) {
        payload.clear();
        return false;
    }

    auto& session = session_it->second;
    session.last_active = now;
    session.link->Push(target, std::move(payload));
    return true;
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

void UdpWorker::CleanupClientSessions(const std::string& socket_key) {
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

void UdpWorker::CleanupAllClientSessions() {
    while (!impl_->client_sessions.empty()) {
        CleanupClientSessions(impl_->client_sessions.begin()->first);
    }
}

udp::socket* UdpWorker::MakeSocket(net::io_context& io_context) {
    memory::ThreadLocalAllocator<udp::socket> alloc;
    udp::socket* raw = alloc.allocate(1);
    try {
        std::construct_at(raw, io_context);
    } catch (...) {
        alloc.deallocate(raw, 1);
        throw;
    }
    return raw;
}

udp::socket* UdpWorker::AttachSocket(const std::string& socket_key, udp::socket* socket) {
    if (!socket) {
        return nullptr;
    }
    UdpSocketPtr owned(socket);
    auto* raw = owned.get();
    impl_->udp_sockets[socket_key] = std::move(owned);
    return raw;
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
    impl_->retired_udp_sockets.push_back(std::move(sock_it->second));
    impl_->udp_sockets.erase(sock_it);
    MaybeShrinkHashContainer(impl_->udp_sockets, 8);
}

void UdpWorker::CloseAllSockets() noexcept {
    while (!impl_->udp_sockets.empty()) {
        CloseSocket(impl_->udp_sockets.begin()->first);
    }
    TryShrinkSequence(impl_->retired_udp_sockets);
}

}  // namespace acpp::proxyman::inbound
