#include "acppnode/app/proxyman/inbound/udp_worker.hpp"

#include "acppnode/common/allocator.hpp"
#include "acppnode/common/container_util.hpp"

#include <asio/steady_timer.hpp>
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
        : wake(io_context)
        , reply_callback(std::move(reply_callback))
        , user_id(user_id) {
        wake.expires_at(net::steady_timer::time_point::max());
    }

    net::steady_timer wake;
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
    impl_->wake.cancel();
}

void UdpWorker::ClientSession::Close() noexcept {
    if (impl_->closed) {
        return;
    }
    impl_->closed = true;
    impl_->input_queue.clear();
    impl_->queued_bytes = 0;
    IoErrorCode ec;
    impl_->wake.cancel(ec);
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

        impl_->wake.expires_at(net::steady_timer::time_point::max());
        auto [ec] = co_await impl_->wake.async_wait(
            net::as_tuple(net::use_awaitable));
        if (ec == io_error::operation_aborted) {
            continue;
        }
        if (ec) {
            co_return buf::MultiBuffer{};
        }
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
