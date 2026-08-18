#include "udp_ingress.hpp"

#include "acppnode/app/proxyman/inbound/receiver_settings.hpp"
#include "acppnode/app/access_log_session.hpp"
#include "acppnode/common/initial_payload.hpp"
#include "acppnode/common/ip_utils.hpp"
#include "acppnode/common/read_prefix_capture.hpp"
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

namespace acpp::worker_detail {

class UdpIngress::PendingUdpReply {
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
    memory::ThreadLocalDeque<UdpIngress::PendingUdpReply> pending;
    size_t queued_bytes = 0;
    UdpIngress::PendingUdpReply* active_reply = nullptr;
    bool shrink_pending_on_drain = false;
};

struct UdpClientSession {
    UdpIngress::ClientSessionPtr link;
    std::chrono::steady_clock::time_point last_active;
};

using UdpClientSessionMap =
    std::unordered_map<
        std::string,
        UdpClientSession>;

}  // namespace

struct UdpIngress::ClientSession::Impl {
    Impl(net::io_context& io_context,
         ReplyCallback reply_callback,
         udp::endpoint reply_endpoint,
         InboundDatagramOwner session_owner)
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
    ErrorCode terminal_error = ErrorCode::OK;
    InboundDatagramOwner session_owner;
};

UdpIngress::ClientSession::ClientSession(
    net::io_context& io_context,
    ReplyCallback reply_callback,
    udp::endpoint reply_endpoint,
    InboundDatagramOwner session_owner)
    : impl_(std::make_unique<Impl>(
          io_context,
          std::move(reply_callback),
          std::move(reply_endpoint),
          std::move(session_owner))) {}

UdpIngress::ClientSession::~ClientSession() noexcept {
    Close();
}

bool UdpIngress::ClientSession::Closed() const noexcept {
    return impl_->closed;
}

bool UdpIngress::ClientSession::Owns(
    const InboundDatagramOwner& owner) const noexcept {
    return impl_->session_owner.Same(owner);
}

void UdpIngress::ClientSession::UpdateReplyEndpoint(
    udp::endpoint endpoint) noexcept {
    impl_->reply_endpoint = std::move(endpoint);
}

bool UdpIngress::ClientSession::Push(
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
        CloseWithError(ErrorCode::RESOURCE_EXHAUSTED);
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

void UdpIngress::ClientSession::Close() noexcept {
    CloseWithError(ErrorCode::OK);
}

void UdpIngress::ClientSession::CloseWithError(ErrorCode error) noexcept {
    if (impl_->closed) {
        return;
    }
    impl_->closed = true;
    impl_->terminal_error = error;
    impl_->input_queue.clear();
    impl_->queued_bytes = 0;
    impl_->WakeReader();
}

net::awaitable<buf::MultiBuffer>
UdpIngress::ClientSession::ReadMultiBuffer() {
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
            if (impl_->terminal_error == ErrorCode::RESOURCE_EXHAUSTED) {
                throw IoSystemError(
                    io_error::no_buffer_space,
                    "UDP client input queue full");
            }
            co_return buf::MultiBuffer{};
        }

        auto [ec] = co_await impl_->reader_signal.async_receive(
            net::as_tuple(net::use_awaitable));
        if (ec) {
            throw IoSystemError(
                io_error::operation_aborted,
                "UDP client input cancelled");
        }
    }
}

net::awaitable<void>
UdpIngress::ClientSession::WriteMultiBuffer(buf::MultiBuffer mb) {
    if (impl_->closed || !impl_->reply_callback) {
        mb.clear();
        throw IoSystemError(
            io_error::operation_aborted,
            "UDP client reply path closed");
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

struct UdpIngress::Impl {
    using UdpSocketMap =
        memory::ThreadLocalUnorderedMap<std::string, UdpIngress::SocketPtr>;

    Impl(std::string tag, std::unique_ptr<::acpp::Inbound> proxy)
        : tag(std::move(tag))
        , proxy(std::move(proxy)) {}

    std::string tag;
    std::unique_ptr<::acpp::Inbound> proxy;
    UdpSocketMap udp_sockets;
    memory::ThreadLocalUnorderedMap<std::string, UdpReplyQueueState> reply_queues;
    memory::ThreadLocalUnorderedMap<std::string, UdpClientSessionMap> client_sessions;
};

UdpIngress::UdpIngress(
    std::string tag,
    std::unique_ptr<::acpp::Inbound> proxy)
    : impl_(std::make_unique<Impl>(std::move(tag), std::move(proxy))) {}

UdpIngress::~UdpIngress() noexcept = default;
UdpIngress::UdpIngress(UdpIngress&&) noexcept = default;
UdpIngress& UdpIngress::operator=(UdpIngress&&) noexcept = default;

void UdpIngress::PendingUdpReplyDeleter::operator()(
    PendingUdpReply* reply) const noexcept {
    delete reply;
}

std::string_view UdpIngress::Tag() const noexcept {
    return impl_->tag;
}

bool UdpIngress::ReplaceHandler(
    std::unique_ptr<::acpp::Inbound> proxy) noexcept {
    if (!proxy) {
        return false;
    }
    if (impl_->proxy) {
        proxy->AdoptWorkerStateFrom(*impl_->proxy);
    }
    impl_->proxy = std::move(proxy);
    return true;
}

void UdpIngress::Close() noexcept {
    CloseAllSockets();
    CleanupAllClientSessions();
    impl_->reply_queues.clear();
    MaybeShrinkHashContainer(impl_->reply_queues, 8);
}

void UdpIngress::ProcessDatagram(const UdpDatagramContext& datagram) {
    if (!impl_->proxy || !datagram.sock || datagram.payload.empty()) {
        return;
    }
    if (!datagram.receiver) {
        LOG_NET_DEBUG(
            "Worker[{}]: UDP datagram missing prepared receiver tag={}",
            datagram.worker_id,
            impl_->tag);
        return;
    }

    const std::string socket_key(datagram.socket_key);
    const auto now = std::chrono::steady_clock::now();

    const std::string client_ip =
        iputil::NormalizeAddressString(datagram.client_endpoint.address());
    const auto normalized_client_addr =
        iputil::NormalizeAddress(datagram.client_endpoint.address());
    auto decoded = impl_->proxy->Process(InboundDatagramRequest{
        .tag = impl_->tag,
        .client_ip = client_ip,
        .payload = datagram.payload,
    });
    if (!decoded) {
        if (datagram.receiver->access_source_ref != 0) {
            session::Context rejected_ctx;
            rejected_ctx.conn_id = session::NewID(datagram.worker_id);
            rejected_ctx.worker_id = datagram.worker_id;
            rejected_ctx.runtime_generation = datagram.runtime_generation;
            rejected_ctx.config_generation = datagram.config_generation;
            rejected_ctx.inbound.tag = datagram.receiver->inbound_tag.empty()
                ? std::string_view(impl_->tag)
                : std::string_view(datagram.receiver->inbound_tag);
            rejected_ctx.inbound.tags = datagram.receiver->RouteInboundTags();
            rejected_ctx.inbound.source_ip = client_ip;
            rejected_ctx.inbound.source_addr = normalized_client_addr;
            rejected_ctx.inbound.source_port = datagram.client_endpoint.port();
            rejected_ctx.inbound.peer_ip = client_ip;
            rejected_ctx.inbound.peer_port = datagram.client_endpoint.port();
            rejected_ctx.inbound.access_source_ref =
                datagram.receiver->access_source_ref;
            rejected_ctx.inbound.protocol = datagram.receiver->protocol;
            rejected_ctx.inbound.transport = "udp";
            rejected_ctx.inbound.security = datagram.receiver->stream_settings.security;
            rejected_ctx.inbound.read_prefix_capture =
                std::make_shared<ReadPrefixCapture>();
            rejected_ctx.inbound.read_prefix_capture->Append(datagram.payload);
            rejected_ctx.content.network = Network::UDP;

            IoErrorCode local_ec;
            const auto local_ep = datagram.sock->local_endpoint(local_ec);
            if (!local_ec && !local_ep.address().is_unspecified()) {
                rejected_ctx.inbound.local_endpoint = tcp::endpoint(
                    iputil::NormalizeAddress(local_ep.address()),
                    local_ep.port());
            }

            app::AccessLogSession access_log(rejected_ctx);
            access_log.Fail(decoded.error());
        }
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
        LOG_NET_DEBUG(
            "Worker[{}]: UDP decode missing authenticated session owner for client={}",
            datagram.worker_id,
            client_key_log());
        return;
    }

    const bool need_new_session = !HasClientSession(socket_key, client_session_key);

    if (need_new_session) {
        if (!decoded->response) {
            LOG_NET_DEBUG("Worker[{}]: UDP decode missing response context for client={}",
                             datagram.worker_id, client_key_log());
            return;
        }

        auto receiver = std::make_shared<proxyman::inbound::ReceiverSettings>(
            *datagram.receiver);

        auto ctx = std::make_shared<session::Context>();
        ctx->conn_id = session::NewID(datagram.worker_id);
        ctx->worker_id = datagram.worker_id;
        ctx->runtime_generation = datagram.runtime_generation;
        ctx->config_generation = datagram.config_generation;
        ctx->inbound.tag = receiver->inbound_tag.empty()
            ? std::string_view(impl_->tag)
            : std::string_view(receiver->inbound_tag);
        ctx->inbound.tags = receiver->RouteInboundTags();
        ctx->inbound.source_ip = client_ip;
        ctx->inbound.source_addr = normalized_client_addr;
        ctx->inbound.source_port = datagram.client_endpoint.port();
        ctx->inbound.peer_ip = client_ip;
        ctx->inbound.peer_port = datagram.client_endpoint.port();
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
        ctx->inbound.transport = "udp";
        ctx->inbound.security = receiver->stream_settings.security;
        ctx->content.speed_limit = decoded->speed_limit;

        auto response_context = std::move(decoded->response);
        udp::socket* sock = datagram.sock;
        auto& reply_sink = datagram.reply_sink;
        const uint32_t worker_id = datagram.worker_id;

        auto reply_cb = [socket_key,
                         sock,
                         response_context = std::move(response_context),
                         &reply_sink,
                         worker_id](UDPPacketView pkt,
                                    const udp::endpoint& reply_endpoint) mutable -> bool {
            auto payload = response_context->Encode(pkt);
            if (payload.empty()) {
                return false;
            }
            return reply_sink.EnqueueUdpReply(
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
        try {
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
                            receiver->dispatch_policy,
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
                        app::AccessLogSession access_log(*ctx);
                        access_log.Fail(ErrorCode::INTERNAL);
                    } catch (...) {
                        LOG_ERROR("Worker[{}]: UDP dispatcher coroutine failed: unknown",
                                  worker_id);
                        app::AccessLogSession access_log(*ctx);
                        access_log.Fail(ErrorCode::INTERNAL);
                    }
                    client_session->Close();
                    co_return;
                },
                net::detached);
        } catch (const std::bad_alloc&) {
            app::AccessLogSession access_log(*ctx);
            access_log.Fail(ErrorCode::RESOURCE_EXHAUSTED);
            client_session->Close();
            return;
        } catch (...) {
            app::AccessLogSession access_log(*ctx);
            access_log.Fail(ErrorCode::INTERNAL);
            client_session->Close();
            return;
        }
    }

    if (!PushClientPayload(
        socket_key,
        client_session_key,
        decoded->target,
        datagram.client_endpoint,
        decoded->session_owner,
        std::move(decoded->payload),
        now)) {
        LOG_NET_DEBUG("Worker[{}]: UDP link enqueue failed for client={}",
                         datagram.worker_id, client_key_log());
    }
}

UdpIngress::ReplyEnqueueResult UdpIngress::EnqueueReply(
    const std::string& socket_key,
    udp::endpoint endpoint,
    buf::MultiBuffer payload) {
    const size_t payload_size = buf::TotalLen(payload);
    if (payload_size == 0) {
        return ReplyEnqueueResult::Rejected;
    }

    auto& queue = impl_->reply_queues[socket_key];
    if (WouldOverflowUdpQueue(
            queue.pending.size(), queue.queued_bytes, payload_size)) {
        return ReplyEnqueueResult::Rejected;
    }
    const bool should_start_send = queue.active_reply == nullptr;
    queue.queued_bytes += payload_size;

    PendingUdpReply reply;
    reply.endpoint = std::move(endpoint);
    reply.payload_size = payload_size;
    reply.payload = std::move(payload);
    queue.pending.push_back(std::move(reply));
    if (queue.pending.size() >= 64 || queue.queued_bytes >= 256 * 1024) {
        queue.shrink_pending_on_drain = true;
    }
    return should_start_send
        ? ReplyEnqueueResult::StartSend
        : ReplyEnqueueResult::Queued;
}

UdpIngress::ReplyEnqueueResult UdpIngress::EnqueueReply(
    const std::string& socket_key,
    udp::endpoint endpoint,
    buf::BufferGuard payload) {
    if (!payload || payload->IsEmpty()) {
        return ReplyEnqueueResult::Rejected;
    }

    const size_t payload_size = payload->Len();
    auto& queue = impl_->reply_queues[socket_key];
    if (WouldOverflowUdpQueue(
            queue.pending.size(), queue.queued_bytes, payload_size)) {
        return ReplyEnqueueResult::Rejected;
    }
    const bool should_start_send = queue.active_reply == nullptr;
    queue.queued_bytes += payload_size;

    PendingUdpReply reply;
    reply.endpoint = std::move(endpoint);
    reply.payload_size = payload_size;
    reply.payload.push_back(payload.release());
    queue.pending.push_back(std::move(reply));
    if (queue.pending.size() >= 64 || queue.queued_bytes >= 256 * 1024) {
        queue.shrink_pending_on_drain = true;
    }
    return should_start_send
        ? ReplyEnqueueResult::StartSend
        : ReplyEnqueueResult::Queued;
}

UdpIngress::PendingUdpReplyPtr
UdpIngress::BeginReplySend(const std::string& socket_key) {
    auto it = impl_->reply_queues.find(socket_key);
    if (it == impl_->reply_queues.end()) {
        return nullptr;
    }

    auto& queue = it->second;
    if (queue.active_reply != nullptr || queue.pending.empty()) {
        return nullptr;
    }

    PendingUdpReplyPtr packet{
        new PendingUdpReply(std::move(queue.pending.front()))};
    queue.queued_bytes -= packet->PayloadSize();
    queue.pending.pop_front();
    packet->PrepareSendBuffers();
    queue.active_reply = packet.get();
    return packet;
}

std::span<const net::const_buffer>
UdpIngress::ReplySendBuffers(const PendingUdpReply& reply) noexcept {
    return reply.SendBuffers();
}

const udp::endpoint&
UdpIngress::ReplyEndpoint(const PendingUdpReply& reply) noexcept {
    return reply.endpoint;
}

bool UdpIngress::CompleteReplySend(
    const std::string& socket_key,
    const PendingUdpReply& completed_reply) {
    auto it = impl_->reply_queues.find(socket_key);
    if (it == impl_->reply_queues.end()) {
        return false;
    }

    auto& queue = it->second;
    if (queue.active_reply != &completed_reply) {
        return false;
    }
    queue.active_reply = nullptr;
    if (queue.pending.empty()) {
        if (queue.shrink_pending_on_drain) {
            TryShrinkSequence(queue.pending);
            queue.shrink_pending_on_drain = false;
        }
        return false;
    }
    return true;
}

void UdpIngress::ClearReplyQueue(const std::string& socket_key) {
    impl_->reply_queues.erase(socket_key);
    MaybeShrinkHashContainer(impl_->reply_queues, 8);
}

bool UdpIngress::HasClientSession(const std::string& socket_key,
                                 const std::string& client_key) const noexcept {
    auto session = FindClientSession(socket_key, client_key);
    return session && !session->Closed();
}

UdpIngress::ClientSessionPtr UdpIngress::FindClientSession(
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

UdpIngress::ClientSessionPtr UdpIngress::CreateClientSession(
    const std::string& socket_key,
    const std::string& client_key,
    net::io_context& io_context,
    ReplyCallback reply_callback,
    udp::endpoint reply_endpoint,
    InboundDatagramOwner session_owner,
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

bool UdpIngress::PushClientPayload(
    const std::string& socket_key,
    const std::string& client_key,
    const TargetAddress& target,
    udp::endpoint reply_endpoint,
    const InboundDatagramOwner& session_owner,
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

void UdpIngress::CleanupIdleClientSessions(
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

void UdpIngress::CleanupClientSessions(const std::string& socket_key) noexcept {
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

void UdpIngress::CleanupAllClientSessions() noexcept {
    while (!impl_->client_sessions.empty()) {
        CleanupClientSessions(impl_->client_sessions.begin()->first);
    }
}

UdpIngress::SocketPtr UdpIngress::AttachSocket(
    const std::string& socket_key,
    SocketPtr socket) {
    if (!socket) {
        return nullptr;
    }
    auto [it, inserted] = impl_->udp_sockets.try_emplace(
        socket_key, socket);
    return inserted ? std::move(socket) : nullptr;
}

UdpIngress::SocketPtr UdpIngress::FindSocket(
    const std::string& socket_key) noexcept {
    auto it = impl_->udp_sockets.find(socket_key);
    return it == impl_->udp_sockets.end() ? nullptr : it->second;
}

std::shared_ptr<const udp::socket> UdpIngress::FindSocket(
    const std::string& socket_key) const noexcept {
    auto it = impl_->udp_sockets.find(socket_key);
    return it == impl_->udp_sockets.end() ? nullptr : it->second;
}

bool UdpIngress::OwnsSocket(
    const std::string& socket_key,
    const udp::socket* socket) const noexcept {
    auto it = impl_->udp_sockets.find(socket_key);
    return socket && it != impl_->udp_sockets.end() &&
        it->second.get() == socket;
}

std::vector<std::string> UdpIngress::SocketKeys() const {
    std::vector<std::string> keys;
    keys.reserve(impl_->udp_sockets.size());
    for (const auto& [socket_key, socket] : impl_->udp_sockets) {
        (void)socket;
        keys.push_back(socket_key);
    }
    return keys;
}

void UdpIngress::CloseSocket(const std::string& socket_key) noexcept {
    CleanupClientSessions(socket_key);
    ClearReplyQueue(socket_key);

    auto sock_it = impl_->udp_sockets.find(socket_key);
    if (sock_it == impl_->udp_sockets.end()) {
        return;
    }

    auto socket = std::move(sock_it->second);
    impl_->udp_sockets.erase(sock_it);
    MaybeShrinkHashContainer(impl_->udp_sockets, 8);

    IoErrorCode ec;
    socket->cancel(ec);
    socket->close(ec);
}

void UdpIngress::CloseAllSockets() noexcept {
    while (!impl_->udp_sockets.empty()) {
        CloseSocket(impl_->udp_sockets.begin()->first);
    }
}

}  // namespace acpp::worker_detail
