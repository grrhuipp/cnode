#include "udp_ingress.hpp"
#include "udp_association_reclaimer.hpp"

#include "acppnode/app/proxyman/inbound/receiver_settings.hpp"
#include "acppnode/common/initial_payload.hpp"
#include "acppnode/common/ip_utils.hpp"
#include "acppnode/common/session.hpp"
#include "acppnode/common/allocator.hpp"
#include "acppnode/common/container_util.hpp"
#include "acppnode/common/string_hash.hpp"
#include "acppnode/features/routing/dispatcher.hpp"
#include "acppnode/infra/config_types.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/infra/runtime_failure.hpp"
#include "acppnode/transport/async_stream.hpp"

#include <asio/as_tuple.hpp>
#include <asio/bind_cancellation_slot.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/experimental/channel.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/this_coro.hpp>

#include <exception>
#include <stdexcept>
#include <utility>

namespace udp_native_lifecycle_fault {
void OnNativeDispatchStage() noexcept;
}

namespace acpp::worker_detail {

class UdpIngress::PendingUdpReply : public memory::ThreadAllocated {
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

template <class Map>
[[nodiscard]] auto FindOrEmplaceStringKey(Map& map, std::string_view key) {
    auto it = map.find(key);
    if (it != map.end()) {
        return std::pair{it, false};
    }
    return map.try_emplace(memory::ThreadLocalString{key});
}

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
    UdpAssociationHook reclaim_hook;
};

using UdpClientSessionMap = memory::ThreadLocalUnorderedMap<
    memory::ThreadLocalString,
    UdpClientSession,
    TransparentStringHash,
    TransparentStringEq>;

[[nodiscard]] bool ShouldReclaim(
    const UdpClientSession& session,
    std::chrono::steady_clock::time_point now,
    std::chrono::seconds idle_timeout) noexcept {
    return !session.link || session.link->Closed() ||
        (idle_timeout.count() > 0 && now - session.last_active > idle_timeout);
}

template <class Function>
class ScopeExit final {
public:
    explicit ScopeExit(Function function) noexcept
        : function_(std::move(function)) {}
    ~ScopeExit() noexcept {
        if (active_) function_();
    }
    ScopeExit(const ScopeExit&) = delete;
    ScopeExit& operator=(const ScopeExit&) = delete;
    void Release() noexcept { active_ = false; }
private:
    Function function_;
    bool active_ = true;
};

template <class Function>
[[nodiscard]] ScopeExit<Function> MakeScopeExit(Function function) noexcept {
    return ScopeExit<Function>(std::move(function));
}

}  // namespace

struct UdpIngress::ClientSession::Impl : memory::ThreadAllocated {
    struct RequestData {
        explicit RequestData(routing::DispatchPolicy dispatch_policy)
            : context(), policy(std::move(dispatch_policy)) {}
        session::Context context;
        routing::DispatchPolicy policy;
        UdpIngress::SocketPtr socket;
        routing::Dispatcher* dispatcher = nullptr;
        net::io_context* io_context = nullptr;
        StatsShard* stats = nullptr;
        TimeoutsConfig timeouts;
        uint32_t worker_id = 0;
    };

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
    transport::CancellationSource cancellation;
    std::optional<RequestData> request;
    UdpIngress* owner = nullptr;
    ClientSession* job_previous = nullptr;
    ClientSession* job_next = nullptr;
    ClientSession* notify_next = nullptr;
    std::weak_ptr<ClientSession> job_pin;
    UdpIngress::ClientSessionPtr notification_pin;
    bool job_registered = false;
    bool job_linked = false;
};

UdpIngress::ClientSession::ClientSession(
    net::io_context& io_context,
    ReplyCallback reply_callback,
    udp::endpoint reply_endpoint,
    InboundDatagramOwner session_owner)
    : impl_(new Impl(
          io_context,
          std::move(reply_callback),
          std::move(reply_endpoint),
          std::move(session_owner))) {}

UdpIngress::ClientSession::~ClientSession() noexcept {
    Close();
}

transport::CancellationSource& UdpIngress::ClientSession::Cancellation() noexcept {
    return impl_->cancellation;
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

    Impl::QueuedInput input{std::move(payload), payload_size};
    impl_->input_queue.push_back(std::move(input));
    impl_->queued_bytes += payload_size;
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
    impl_->cancellation.Stop(error);
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

struct UdpIngress::Impl : memory::ThreadAllocated {
    using UdpSocketMap = memory::ThreadLocalUnorderedMap<
        memory::ThreadLocalString,
        UdpIngress::SocketPtr,
        TransparentStringHash,
        TransparentStringEq>;
    using ReplyQueueMap = memory::ThreadLocalUnorderedMap<
        memory::ThreadLocalString,
        UdpReplyQueueState,
        TransparentStringHash,
        TransparentStringEq>;
    using ClientSessionOuterMap = memory::ThreadLocalUnorderedMap<
        memory::ThreadLocalString,
        UdpClientSessionMap,
        TransparentStringHash,
        TransparentStringEq>;

    enum class State : uint8_t { Running, Stopping, Drained };

    Impl(std::string tag, std::unique_ptr<::acpp::Inbound> proxy,
         UdpAssociationReclaimer& reclaimer, net::io_context& io_context)
        : tag(std::string_view(tag))
        , proxy(std::move(proxy))
        , reclaimer(reclaimer)
        , completion_signal(io_context, 1) {}

    memory::ThreadLocalString tag;
    std::unique_ptr<::acpp::Inbound> proxy;
    UdpAssociationReclaimer& reclaimer;
    UdpSocketMap udp_sockets;
    ReplyQueueMap reply_queues;
    ClientSessionOuterMap client_sessions;
    net::experimental::channel<void(IoErrorCode)> completion_signal;
    ClientSession* jobs = nullptr;
    size_t outstanding_jobs = 0;
    size_t join_observers = 0;
    State state = State::Running;
};

UdpIngress::UdpIngress(
    std::string tag,
    std::unique_ptr<::acpp::Inbound> proxy,
    UdpAssociationReclaimer& reclaimer,
    net::io_context& io_context)
    : impl_(new Impl(std::move(tag), std::move(proxy), reclaimer, io_context)) {}

UdpIngress::~UdpIngress() noexcept {
    if (impl_->outstanding_jobs != 0) {
        FailRuntime("udp-ingress", "destroyed with native dispatch jobs outstanding");
    }
    CleanupAllClientSessions();
}

void UdpIngress::PendingUdpReplyDeleter::operator()(
    PendingUdpReply* reply) const noexcept {
    delete reply;
}

std::string_view UdpIngress::Tag() const noexcept {
    return impl_->tag;
}

UdpIngress::ResourceStats UdpIngress::GetResourceStats() const noexcept {
    ResourceStats stats{};
    for (const auto& [socket_key, sessions] : impl_->client_sessions) {
        (void)socket_key;
        for (const auto& [client_key, session] : sessions) {
            (void)client_key;
            ++stats.associations;
            if (!session.link || session.link->Closed()) {
                ++stats.closed_associations;
            }
            if (session.link) {
                stats.input_datagrams += session.link->impl_->input_queue.size();
                stats.input_bytes += session.link->impl_->queued_bytes;
            }
        }
    }
    stats.native_dispatches = impl_->outstanding_jobs;
    for (const auto& [socket_key, queue] : impl_->reply_queues) {
        (void)socket_key;
        stats.reply_datagrams += queue.pending.size();
        stats.reply_bytes += queue.queued_bytes;
        if (queue.active_reply) {
            ++stats.active_reply_senders;
            ++stats.reply_datagrams;
            stats.reply_bytes += queue.active_reply->PayloadSize();
        }
    }
    return stats;
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

void UdpIngress::RequestStop() noexcept {
    if (impl_->state != Impl::State::Running) return;
    impl_->state = Impl::State::Stopping;
    CloseAllSockets();
    CleanupAllClientSessions();
    impl_->reply_queues.clear();

    ClientSession* notify = impl_->jobs;
    impl_->jobs = nullptr;
    for (auto* job = notify; job;) {
        auto* next = job->impl_->job_next;
        job->impl_->notification_pin = job->impl_->job_pin.lock();
        job->impl_->notify_next = next;
        job->impl_->job_previous = nullptr;
        job->impl_->job_next = nullptr;
        job->impl_->job_linked = false;
        job = next;
    }
    while (notify) {
        auto* current = notify;
        notify = current->impl_->notify_next;
        current->impl_->notify_next = nullptr;
        auto pin = std::move(current->impl_->notification_pin);
        if (pin) pin->Close();
    }
    if (impl_->outstanding_jobs == 0) impl_->state = Impl::State::Drained;
}

net::awaitable<void> UdpIngress::AsyncJoin() {
    const bool previous_throw_setting = co_await net::this_coro::throw_if_cancelled();
    co_await net::this_coro::throw_if_cancelled(false);
    std::exception_ptr failure;
    const bool observer_conflict = impl_->join_observers != 0;
    if (!observer_conflict) {
        ++impl_->join_observers;
        struct ReleaseObserver {
            size_t& observers;
            ~ReleaseObserver() { --observers; }
        } release{impl_->join_observers};
        try {
            while (impl_->outstanding_jobs != 0) {
                auto [ec] = co_await impl_->completion_signal.async_receive(
                    net::as_tuple(asio::bind_cancellation_slot(
                        asio::cancellation_slot{}, net::use_awaitable)));
                if (ec && impl_->outstanding_jobs != 0)
                    throw IoSystemError(ec, "UDP native dispatch join failed");
            }
            if (impl_->state == Impl::State::Stopping)
                impl_->state = Impl::State::Drained;
        } catch (...) {
            failure = std::current_exception();
        }
    }
    co_await net::this_coro::throw_if_cancelled(previous_throw_setting);
    if (observer_conflict)
        throw std::logic_error("UdpIngress AsyncJoin supports one observer");
    if (failure) std::rethrow_exception(failure);
}

void UdpIngress::FinishNativeJob(ClientSession& session) noexcept {
    session.Close();
    RetireNativeJob(session);
}

void UdpIngress::RollbackNativeJob(ClientSession& session) noexcept {
    RetireNativeJob(session);
}

void UdpIngress::RetireNativeJob(ClientSession& session) noexcept {
    auto& job = *session.impl_;
    if (!job.job_registered) return;
    if (job.job_linked) {
        if (job.job_previous)
            job.job_previous->impl_->job_next = job.job_next;
        else if (impl_->jobs == &session)
            impl_->jobs = job.job_next;
        if (job.job_next)
            job.job_next->impl_->job_previous = job.job_previous;
    }
    job.job_previous = nullptr;
    job.job_next = nullptr;
    job.job_registered = false;
    job.job_linked = false;
    job.owner = nullptr;
    job.job_pin.reset();
    job.request.reset();
    if (impl_->outstanding_jobs == 0) {
        FailRuntime("udp-ingress", "native dispatch completion underflow");
    }
    --impl_->outstanding_jobs;
    if (impl_->state == Impl::State::Stopping && impl_->outstanding_jobs == 0)
        impl_->state = Impl::State::Drained;
    if (impl_->join_observers != 0 && impl_->outstanding_jobs == 0) {
        try {
            if (!impl_->completion_signal.try_send(IoErrorCode{}))
                FailRuntime("udp-ingress-join", "completion event channel was full");
        } catch (...) {
            FailRuntime("udp-ingress-join", "failed to signal native job drain");
        }
    }
}

net::awaitable<void> UdpIngress::RunNativeDispatch(ClientSessionPtr client_session) {
    auto& job = *client_session->impl_;
    auto& request = *job.request;
    try {
        RelayResult result = co_await request.dispatcher->Dispatch(
            *request.io_context, request.policy, nullptr,
            transport::Link{client_session.get(), client_session.get()},
            InitialPayload{}, request.context, *request.stats, request.timeouts);
        if (result.error != ErrorCode::OK) {
            LOG_CONN_DEBUG(request.context,
                "[UDP] dispatcher session end: {} up={}B down={}B",
                ErrorCodeToString(result.error), result.bytes_up,
                result.bytes_down);
        }
    } catch (const std::exception& e) {
        LOG_ERROR("Worker[{}]: UDP dispatcher coroutine failed: {}",
                  request.worker_id, e.what());
    } catch (...) {
        LOG_ERROR("Worker[{}]: UDP dispatcher coroutine failed: unknown",
                  request.worker_id);
    }
    client_session->Close();
    co_return;
}

void UdpIngress::ProcessDatagram(const UdpDatagramContext& datagram) {
    if (impl_->state != Impl::State::Running || !impl_->proxy ||
        !datagram.sock || datagram.payload.empty()) {
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
    auto datagram_socket = FindSocket(socket_key);
    if (!datagram_socket || datagram_socket.get() != datagram.sock) return;
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

    auto current_session = FindClientSession(socket_key, client_session_key);
    if (current_session) {
        auto outer = impl_->client_sessions.find(socket_key);
        auto row = outer->second.find(client_session_key);
        if (row != outer->second.end() && ShouldReclaim(
                row->second, now, row->second.reclaim_hook.idle_timeout)) {
            ReclaimAssociation(row->second.reclaim_hook, now);
            // Synchronous cancellation may retire or replace the listener.
            // The decoded packet cannot create a request for its old socket.
            if (!OwnsSocket(socket_key, datagram.sock)) return;
            current_session.reset();
        }
    }
    const bool need_new_session = !current_session || current_session->Closed();
    ClientSessionPtr packet_session = current_session;
    ClientSessionPtr preparation_session;
    auto preparation_guard = MakeScopeExit([&]() noexcept {
        if (preparation_session) preparation_session->Close();
    });

    if (need_new_session) {
        if (!decoded->response) {
            LOG_NET_DEBUG("Worker[{}]: UDP decode missing response context for client={}",
                             datagram.worker_id, client_key_log());
            return;
        }

        auto stable_socket = datagram_socket;
        if (impl_->state != Impl::State::Running) return;

        auto response_context = std::move(decoded->response);
        udp::socket* sock = stable_socket.get();
        auto& reply_sink = datagram.reply_sink;
        const uint32_t worker_id = datagram.worker_id;
        auto reply_cb = [socket_key, stable_socket, sock,
                         response_context = std::move(response_context),
                         &reply_sink, worker_id](UDPPacketView pkt,
                                    const udp::endpoint& reply_endpoint) mutable -> bool {
            (void)stable_socket;
            auto payload = response_context->Encode(pkt);
            if (payload.empty()) return false;
            return reply_sink.EnqueueUdpReply(socket_key, sock, reply_endpoint,
                                               std::move(payload), worker_id);
        };

        auto client_session = CreateClientSession(
            socket_key, client_session_key, datagram.io_context,
            std::move(reply_cb), datagram.client_endpoint,
            decoded->session_owner, now, datagram.timeouts.SessionIdleTimeout());
        if (!client_session) return;
        packet_session = client_session;
        preparation_session = client_session;
        if (impl_->state != Impl::State::Running ||
            !OwnsSocket(socket_key, stable_socket.get())) {
            client_session->Close();
            return;
        }
        auto& session_impl = *client_session->impl_;
        session_impl.request.emplace(datagram.receiver->dispatch_policy);
        auto& request = *session_impl.request;
        auto& ctx = request.context;
        ctx.conn_id = session::NewID(datagram.worker_id);
        ctx.worker_id = datagram.worker_id;
        ctx.runtime_generation = datagram.runtime_generation;
        ctx.config_generation = datagram.config_generation;
        const std::string_view inbound_tag = datagram.receiver->inbound_tag.empty()
            ? std::string_view(impl_->tag)
            : std::string_view(datagram.receiver->inbound_tag);
        ctx.inbound.tag.assign(inbound_tag);
        if (const auto* route_tags = datagram.receiver->RouteInboundTags()) {
            ctx.inbound.tags.reserve(route_tags->size());
            for (const auto& route_tag : *route_tags)
                ctx.inbound.tags.emplace_back(route_tag);
        }
        ctx.inbound.source_ip.assign(client_ip);
        ctx.inbound.source_addr = normalized_client_addr;
        ctx.inbound.source_port = datagram.client_endpoint.port();
        ctx.inbound.peer_ip.assign(client_ip);
        ctx.inbound.peer_port = datagram.client_endpoint.port();
        IoErrorCode local_ec;
        const auto local_ep = datagram.sock->local_endpoint(local_ec);
        if (!local_ec && !local_ep.address().is_unspecified()) {
            const auto local_addr = iputil::NormalizeAddress(local_ep.address());
            ctx.inbound.local_endpoint = tcp::endpoint(local_addr, local_ep.port());
        }
        ctx.content.network = Network::UDP;
        ctx.outbound.original_target = decoded->target;
        ctx.outbound.target = decoded->target;
        ctx.inbound.user_id = decoded->user_id;
        ctx.inbound.user_email.assign(decoded->user_email);
        ctx.inbound.protocol.assign(datagram.receiver->protocol);
        ctx.inbound.transport = "udp";
        ctx.inbound.security.assign(datagram.receiver->stream_settings.security);
        ctx.content.speed_limit = decoded->speed_limit;
        request.socket = stable_socket;
        request.dispatcher = &datagram.dispatcher;
        request.io_context = &datagram.io_context;
        request.stats = &datagram.stats;
        request.timeouts = datagram.timeouts;
        request.worker_id = worker_id;
        session_impl.owner = this;
        session_impl.job_registered = true;
        session_impl.job_pin = client_session;
        session_impl.job_previous = nullptr;
        session_impl.job_next = impl_->jobs;
        session_impl.job_linked = true;
        if (impl_->jobs) impl_->jobs->impl_->job_previous = client_session.get();
        impl_->jobs = client_session.get();
        ++impl_->outstanding_jobs;
#ifdef CNODE_TEST_UDP_NATIVE_LIFECYCLE_FAULT
        // Test-only arm point: the next C++ allocations are the real coroutine
        // frames. No production path or synthetic throw is introduced.
        ::udp_native_lifecycle_fault::OnNativeDispatchStage();
#endif
        try {
            net::co_spawn(
                datagram.io_context.get_executor(),
                RunNativeDispatch(client_session),
                [this, client_session](std::exception_ptr error) noexcept {
                    (void)error;
                    FinishNativeJob(*client_session);
                });
        } catch (...) {
            RollbackNativeJob(*client_session);
            client_session->Close();
            throw;
        }
    }

    if (!packet_session || packet_session->Closed() ||
        !packet_session->Owns(decoded->session_owner)) {
        decoded->payload.clear();
        return;
    }
    auto sessions = impl_->client_sessions.find(socket_key);
    if (sessions != impl_->client_sessions.end()) {
        auto row = sessions->second.find(client_session_key);
        if (row != sessions->second.end() && row->second.link == packet_session)
            row->second.last_active = now;
    }
    packet_session->UpdateReplyEndpoint(datagram.client_endpoint);
    if (!packet_session->Push(decoded->target, std::move(decoded->payload))) {
        LOG_NET_DEBUG("Worker[{}]: UDP link enqueue failed for client={}",
                         datagram.worker_id, client_key_log());
    } else if (preparation_session) {
        preparation_session.reset();
        preparation_guard.Release();
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

    auto [queue_it, inserted] = FindOrEmplaceStringKey(
        impl_->reply_queues, socket_key);
    (void)inserted;
    auto& queue = queue_it->second;
    if (WouldOverflowUdpQueue(
            queue.pending.size(), queue.queued_bytes, payload_size)) {
        return ReplyEnqueueResult::Rejected;
    }
    const bool should_start_send = queue.active_reply == nullptr;

    PendingUdpReply reply;
    reply.endpoint = std::move(endpoint);
    reply.payload_size = payload_size;
    reply.payload = std::move(payload);
    queue.pending.push_back(std::move(reply));
    queue.queued_bytes += payload_size;
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
    auto [queue_it, inserted] = FindOrEmplaceStringKey(
        impl_->reply_queues, socket_key);
    (void)inserted;
    auto& queue = queue_it->second;
    if (WouldOverflowUdpQueue(
            queue.pending.size(), queue.queued_bytes, payload_size)) {
        return ReplyEnqueueResult::Rejected;
    }
    const bool should_start_send = queue.active_reply == nullptr;

    PendingUdpReply reply;
    reply.endpoint = std::move(endpoint);
    reply.payload_size = payload_size;
    reply.payload.push_back(std::move(payload));
    queue.pending.push_back(std::move(reply));
    queue.queued_bytes += payload_size;
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

void UdpIngress::ClearReplyQueue(std::string_view socket_key) {
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
    std::chrono::steady_clock::time_point now,
    std::chrono::seconds idle_timeout) {
    if (impl_->state != Impl::State::Running) return nullptr;
    auto session = memory::AllocateShared<ClientSession>(
        io_context,
        std::move(reply_callback),
        std::move(reply_endpoint),
        std::move(session_owner));
    auto [sessions_it, group_inserted] = FindOrEmplaceStringKey(
        impl_->client_sessions, socket_key);
    (void)group_inserted;
    auto& sessions = sessions_it->second;
    auto session_it = sessions.find(std::string_view(client_key));
    if (session_it == sessions.end()) {
        auto [inserted_it, inserted] = sessions.try_emplace(
            memory::ThreadLocalString{std::string_view(client_key)},
            UdpClientSession{.link = session, .last_active = now});
        if (inserted) {
            impl_->reclaimer.Register(inserted_it->second.reclaim_hook, *this,
                sessions_it->first, inserted_it->first, idle_timeout);
        }
    } else {
        auto previous = std::move(session_it->second.link);
        impl_->reclaimer.Unregister(session_it->second.reclaim_hook);
        session_it->second.link = session;
        session_it->second.last_active = now;
        impl_->reclaimer.Register(session_it->second.reclaim_hook, *this,
            sessions_it->first, session_it->first, idle_timeout);
        // Close may synchronously call CloseSocket and erase this replacement.
        // Do not access map iterators or key views after invoking it.
        if (previous) previous->Close();
    }
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

void UdpIngress::ReclaimAssociation(
    UdpAssociationHook& hook,
    std::chrono::steady_clock::time_point now) noexcept {
    auto outer = impl_->client_sessions.find(hook.socket_key);
    if (outer == impl_->client_sessions.end()) {
        impl_->reclaimer.Unregister(hook);
        return;
    }
    auto row = outer->second.find(hook.client_key);
    if (row == outer->second.end() || &row->second.reclaim_hook != &hook) {
        impl_->reclaimer.Unregister(hook);
        return;
    }
    if (!ShouldReclaim(row->second, now, hook.idle_timeout)) return;
    auto session = row->second.link;
    const bool idle = session && !session->Closed() &&
        hook.idle_timeout.count() > 0 &&
        now - row->second.last_active > hook.idle_timeout;
    impl_->reclaimer.Unregister(row->second.reclaim_hook);
    outer->second.erase(row);
    // Release the last group before Close(): cancellation subscribers may
    // synchronously re-enter this ingress and erase the same socket key.
    if (outer->second.empty()) impl_->client_sessions.erase(outer);
    if (idle) session->Close();
}

void UdpIngress::CleanupClientSessions(std::string_view socket_key) noexcept {
    auto sessions_it = impl_->client_sessions.find(socket_key);
    if (sessions_it == impl_->client_sessions.end()) {
        return;
    }

    for (auto& [client_key, session] : sessions_it->second) {
        (void)client_key;
        impl_->reclaimer.Unregister(session.reclaim_hook);
    }
    auto detached = impl_->client_sessions.extract(sessions_it);
    for (auto& [client_key, session] : detached.mapped()) {
        (void)client_key;
        if (session.link) session.link->Close();
    }
}

void UdpIngress::CleanupAllClientSessions() noexcept {
    while (!impl_->client_sessions.empty()) {
        CleanupClientSessions(impl_->client_sessions.begin()->first);
    }
}

UdpIngress::SocketPtr UdpIngress::AttachSocket(
    const std::string& socket_key,
    SocketPtr socket) {
    if (!socket || impl_->state != Impl::State::Running) {
        return nullptr;
    }
    if (impl_->udp_sockets.find(socket_key) != impl_->udp_sockets.end()) {
        return nullptr;
    }
    auto [it, inserted] = impl_->udp_sockets.try_emplace(
        memory::ThreadLocalString{std::string_view(socket_key)}, socket);
    (void)it;
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

void UdpIngress::CloseSocket(std::string_view socket_key) noexcept {
    // Find in every independent table before extraction can invalidate a key
    // view borrowed from any one of those tables.
    auto sessions_it = impl_->client_sessions.find(socket_key);
    auto reply_it = impl_->reply_queues.find(socket_key);
    auto sock_it = impl_->udp_sockets.find(socket_key);
    SocketPtr socket_identity = sock_it == impl_->udp_sockets.end()
        ? SocketPtr{} : sock_it->second;

    ClientSession* notify = nullptr;
    for (auto* job = impl_->jobs; job;) {
        auto* next = job->impl_->job_next;
        if (socket_identity && job->impl_->request &&
            job->impl_->request->socket == socket_identity) {
            if (job->impl_->job_previous)
                job->impl_->job_previous->impl_->job_next = next;
            else
                impl_->jobs = next;
            if (next) next->impl_->job_previous = job->impl_->job_previous;
            job->impl_->job_previous = nullptr;
            job->impl_->job_next = nullptr;
            job->impl_->job_linked = false;
            job->impl_->notification_pin = job->impl_->job_pin.lock();
            job->impl_->notify_next = notify;
            notify = job;
        }
        job = next;
    }
    Impl::ClientSessionOuterMap::node_type detached_sessions;
    if (sessions_it != impl_->client_sessions.end()) {
        for (auto& [client_key, session] : sessions_it->second) {
            (void)client_key;
            impl_->reclaimer.Unregister(session.reclaim_hook);
        }
        detached_sessions = impl_->client_sessions.extract(sessions_it);
    }

    Impl::ReplyQueueMap::node_type detached_replies;
    if (reply_it != impl_->reply_queues.end()) {
        detached_replies = impl_->reply_queues.extract(reply_it);
    }

    Impl::UdpSocketMap::node_type detached_socket;
    if (sock_it != impl_->udp_sockets.end()) {
        detached_socket = impl_->udp_sockets.extract(sock_it);
    }

    while (notify) {
        auto* current = notify;
        notify = current->impl_->notify_next;
        current->impl_->notify_next = nullptr;
        auto pin = std::move(current->impl_->notification_pin);
        if (pin) pin->Close();
    }

    // All views into the live maps are now retired before callbacks can re-enter.
    if (!detached_sessions.empty()) {
        for (auto& [client_key, session] : detached_sessions.mapped()) {
            (void)client_key;
            if (session.link) session.link->Close();
        }
    }
    (void)detached_replies;

    auto socket = detached_socket.empty()
        ? SocketPtr{}
        : std::move(detached_socket.mapped());
    if (socket) {
        IoErrorCode ec;
        socket->cancel(ec);
        socket->close(ec);
    }
}

void UdpIngress::CloseAllSockets() noexcept {
    while (!impl_->udp_sockets.empty()) {
        CloseSocket(impl_->udp_sockets.begin()->first);
    }
}

}  // namespace acpp::worker_detail
