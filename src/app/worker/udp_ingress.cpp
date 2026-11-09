#include "udp_ingress.hpp"
#include "udp_association_reclaimer.hpp"
#include "udp_handoff_directory.hpp"
#include "app/session_capabilities.hpp"
#include "../../common/awaitable_task_group.hpp"
#include "app/proxyman/inbound/factory.hpp"
#include "../../proxy/inbound_admission.hpp"

#include "app/proxyman/inbound/receiver_settings.hpp"
#include "common/initial_payload.hpp"
#include "common/ip_utils.hpp"
#include "common/session.hpp"
#include "common/allocator.hpp"
#include "common/container_util.hpp"
#include "common/string_hash.hpp"
#include "features/routing/dispatcher.hpp"
#include "infra/config_types.hpp"
#include "infra/log.hpp"
#include "infra/runtime_failure.hpp"
#include "transport/async_stream.hpp"

#include <asio/as_tuple.hpp>
#include <asio/bind_cancellation_slot.hpp>
#include <asio/co_spawn.hpp>
#include <asio/experimental/channel.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/this_coro.hpp>

#include <exception>
#include <limits>
#include <stdexcept>
#include <utility>

namespace worker_detail {

void UdpIngress::PendingUdpReply::PrepareSendBuffers() {
    send_buffers.Clear();
    send_buffers.AppendMultiBuffer(payload);
}

std::span<const net::const_buffer>
UdpIngress::PendingUdpReply::SendBuffers() const noexcept {
    return send_buffers.Span();
}

namespace {

using proxy::AdmitNativeAssociation;
using proxy::NativeAssociationAdmission;

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
    uint64_t active_id = 0;
    size_t active_payload_size = 0;
};

[[nodiscard]] bool WouldOverflowUdpQueue(
    const UdpReplyQueueState& queue,
    size_t payload_size) noexcept {
    return WouldOverflowUdpQueue(
        queue.pending.size(), queue.queued_bytes, payload_size);
}

struct UdpClientSession {
    UdpIngress::ClientSessionPtr link;
    // Valid uplink activity only; the reclaimer re-checks it lazily when the
    // row's deadline passes, so packets never re-key the maintenance heap.
    std::chrono::steady_clock::time_point last_active;
    UdpAssociationHook reclaim_hook;
};

using UdpClientSessionMap = memory::ThreadLocalUnorderedMap<
    ClientSessionKey,
    UdpClientSession,
    ClientSessionKeyHash>;

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

bool UdpIngress::ReplyRoute::Send(UDPPacketView packet, const udp::endpoint& endpoint) {
    auto payload = response->Encode(packet);
    if (payload.empty()) return false;
    return sink->EnqueueUdpReply(socket_key, socket.get(), endpoint, std::move(payload), worker_id);
}

struct UdpIngress::ClientSession::Impl : memory::ThreadAllocated {
    struct RequestData {
        explicit RequestData(routing::DispatchPolicy dispatch_policy)
            : context(), policy(std::move(dispatch_policy)) {}
        session::Context context;
        routing::DispatchPolicy policy;
        routing::Dispatcher* dispatcher = nullptr;
        net::io_context* io_context = nullptr;
        StatsShard* stats = nullptr;
        TimeoutsConfig timeouts;
        uint32_t worker_id = 0;
        // Owned copy of the authenticating credential's profile.
        UserProfile profile;
        std::shared_ptr<UserOnlineTracker> tracker_owner;
        UserOnlineTracker* tracker = nullptr;
        ConnectionLimiter* limiter = nullptr;
        uint32_t* active_sessions = nullptr;
    };

    Impl(net::io_context& io_context,
         ReplyRoute reply,
         udp::endpoint reply_endpoint,
         InboundDatagramOwner session_owner,
         UdpResourceBudget& budget,
         UdpResourceBudget::AssociationLease association)
        : association(std::move(association))
        , budget(&budget)
        , reader_signal(io_context, 1)
        , reply(std::move(reply))
        , reply_endpoint(std::move(reply_endpoint))
        , session_owner(std::move(session_owner)) {}

    void WakeReader() {
        (void)reader_signal.try_send(IoErrorCode{});
    }

    UdpResourceBudget::AssociationLease association;
    UdpResourceBudget* budget;
    SignalChannel reader_signal;
    ReplyRoute reply;
    udp::endpoint reply_endpoint;
    struct QueuedInput {
        buf::MultiBuffer payload;
        size_t bytes = 0;
        UdpResourceBudget::PayloadReservation reservation;
    };
    memory::ThreadLocalDeque<QueuedInput> input_queue;
    size_t queued_bytes = 0;
    bool closed = false;
    ErrorCode terminal_error = ErrorCode::OK;
    InboundDatagramOwner session_owner;
    transport::CancellationSource cancellation;
    std::optional<RequestData> request;
    ClientSession* job_previous = nullptr;
    ClientSession* job_next = nullptr;
    ClientSession* notify_next = nullptr;
    std::weak_ptr<ClientSession> job_pin;
    UdpIngress::ClientSessionPtr notification_pin;
    bool job_registered = false;
    bool job_linked = false;
    // The row hook naming this session as its live link; cleared on unlink.
    UdpAssociationHook* association_hook = nullptr;
    std::shared_ptr<UdpHandoffRecord> handoff_record;
    UdpIngress* owner = nullptr;
};

UdpIngress::ClientSession::ClientSession(
    net::io_context& io_context,
    ReplyRoute reply,
    udp::endpoint reply_endpoint,
    InboundDatagramOwner session_owner,
    UdpResourceBudget& budget,
    UdpResourceBudget::AssociationLease association)
    : impl_(new Impl(
          io_context,
          std::move(reply),
          std::move(reply_endpoint),
          std::move(session_owner), budget, std::move(association))) {}

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
    const size_t payload_size = payload.byte_size();
    if (Closed()) {
        payload.clear();
        return false;
    }
    if (WouldOverflowUdpQueue(
            impl_->input_queue.size(), impl_->queued_bytes, payload_size)) {
        payload.clear();
        CloseWithError(ErrorCode::RESOURCE_EXHAUSTED);
        return false;
    }

    if (!buf::SetUdpTarget(payload, target)) return false;
    auto reservation = impl_->budget->ReservePayload(payload);
    if (!reservation) return false;

    Impl::QueuedInput input{std::move(payload), payload_size, std::move(reservation)};
    impl_->input_queue.push_back(std::move(input));
    impl_->queued_bytes += payload_size;
    impl_->WakeReader();
    return true;
}

void UdpIngress::ClientSession::Close() noexcept {
    CloseWithError(ErrorCode::OK);
}

net::awaitable<buf::MultiBuffer>
UdpIngress::ClientSession::ReadMultiBuffer() {
    while (true) {
        if (!impl_->input_queue.empty()) {
            auto input = std::move(impl_->input_queue.front());
            impl_->queued_bytes -= std::min(impl_->queued_bytes, input.bytes);
            impl_->input_queue.pop_front();
            co_return std::move(input.payload);
        }

        if (impl_->closed) {
            if (impl_->terminal_error == ErrorCode::RESOURCE_EXHAUSTED) {
                throw IoSystemError(
                    io_error::no_buffer_space,
                    "UDP client input queue full");
            }
            if (impl_->terminal_error != ErrorCode::OK) {
                throw transport::LinkError(impl_->terminal_error);
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
    if (Closed() || !impl_->reply.Valid()) {
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

    if (!impl_->reply.Send(UDPPacketView{*datagram.target, payload}, impl_->reply_endpoint)) {
        mb.clear();
        throw IoSystemError(
            io_error::fault, "UDP client reply was rejected");
    }
    mb.clear();
    co_return;
}

struct UdpIngress::Impl : memory::ThreadAllocated {
    struct BoundSocket {
        UdpIngress::SocketPtr socket;
        // Resolved once at attachment; the bound address never changes.
        std::optional<tcp::endpoint> local_endpoint;
        InboundDatagramAssociationIndex associations;
    };
    using UdpSocketMap = memory::ThreadLocalUnorderedMap<
        memory::ThreadLocalString,
        BoundSocket,
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

    Impl(std::string_view tag, std::unique_ptr<::Inbound> proxy,
         UdpAssociationReclaimer& reclaimer, UdpResourceBudget& budget,
         net::io_context& io_context)
        : tag(tag)
        , proxy(std::move(proxy))
        , reclaimer(reclaimer)
        , budget(budget)
        , completion_signal(io_context, 1) {}

    [[nodiscard]] std::optional<PendingUdpReply> BeginReplySend(
        UdpReplyQueueState& queue) {
        if (queue.active_id != 0 || queue.pending.empty()) return std::nullopt;
        if (last_reply_id == std::numeric_limits<uint64_t>::max())
            throw IoSystemError(io_error::no_buffer_space, "UDP reply send generation exhausted");

        // Prepare any scatter spill before committing the queue handoff. Ordinary
        // packets move straight into their sender's frame without a heap node.
        queue.pending.front().PrepareSendBuffers();
        std::optional<PendingUdpReply> packet{std::in_place, std::move(queue.pending.front())};
        packet->id = ++last_reply_id;
        queue.queued_bytes -= packet->payload_size;
        queue.pending.pop_front();
        queue.active_id = packet->id;
        queue.active_payload_size = packet->payload_size;
        return packet;
    }

    memory::ThreadLocalString tag;
    std::unique_ptr<::Inbound> proxy;
    UdpAssociationReclaimer& reclaimer;
    UdpResourceBudget& budget;
    UdpSocketMap udp_sockets;
    ReplyQueueMap reply_queues;
    ClientSessionOuterMap client_sessions;
    SignalChannel completion_signal;
    UdpHandoffDirectory directory;
    ClientSession* jobs = nullptr;
    size_t outstanding_jobs = 0;
    size_t join_observers = 0;
    uint64_t last_reply_id = 0;
    State state = State::Running;
    void Link(UdpIngress& owner, UdpClientSession& row, std::string_view socket_key,
              const ClientSessionKey& client_key, std::chrono::seconds idle_timeout) noexcept {
        reclaimer.Register(row.reclaim_hook, owner, socket_key, client_key, idle_timeout,
                           UdpAssociationExpiry(row.last_active, idle_timeout));
        row.link->impl_->association_hook = &row.reclaim_hook;
    }
    void SetLocalAssociation(const UdpAssociationHook& hook,
                             InboundDatagramAssociation* association) noexcept {
        if (!hook.client_key || !hook.client_key->session_id) return;
        auto socket = udp_sockets.find(hook.socket_key);
        if (socket == udp_sockets.end()) return;
        const auto& key = *hook.client_key;
        auto entry = socket->second.associations.find(
            InboundDatagramAssociationKey{key.owner, *key.session_id, key.configuration});
        if (entry != socket->second.associations.end()) entry->second = association;
    }
    void Unlink(UdpClientSession& row) noexcept {
        const auto& hook = row.reclaim_hook;
        if (hook.client_key && hook.client_key->session_id) {
            auto socket = udp_sockets.find(hook.socket_key);
            if (socket != udp_sockets.end()) {
                const auto& key = *hook.client_key;
                socket->second.associations.erase(
                    InboundDatagramAssociationKey{key.owner, *key.session_id, key.configuration});
            }
        }
        reclaimer.Unregister(row.reclaim_hook);
        if (row.link) row.link->impl_->association_hook = nullptr;
    }
};

void UdpIngress::ClientSession::CloseWithError(ErrorCode error) noexcept {
    if (impl_->closed) {
        return;
    }
    impl_->closed = true;
    impl_->terminal_error = error;
    // Closure is the row's reclaim event. Re-arm before cancellation callbacks
    // can re-enter the ingress and unlink the row.
    if (auto* hook = impl_->association_hook) {
        hook->owner->impl_->SetLocalAssociation(*hook, nullptr);
        hook->owner->impl_->reclaimer.Rearm(*hook, UdpAssociationHook::TimePoint::min());
    }
    impl_->cancellation.Stop(error);
    impl_->input_queue.clear();
    impl_->queued_bytes = 0;
    impl_->WakeReader();
}

UdpIngress::UdpIngress(
    std::string_view tag,
    std::unique_ptr<::Inbound> proxy,
    UdpAssociationReclaimer& reclaimer,
    UdpResourceBudget& budget,
    net::io_context& io_context)
    : impl_(new Impl(tag, std::move(proxy), reclaimer, budget, io_context)) {}

UdpIngress::~UdpIngress() noexcept {
    if (impl_->outstanding_jobs != 0) {
        FailRuntime("udp-ingress", "destroyed with native dispatch jobs outstanding");
    }
    CleanupAllClientSessions();
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
        if (queue.active_id != 0) {
            ++stats.active_reply_senders;
            ++stats.reply_datagrams;
            stats.reply_bytes += queue.active_payload_size;
        }
    }
    return stats;
}

bool UdpIngress::ReplaceHandler(
    std::unique_ptr<::Inbound> proxy) noexcept {
    if (!proxy) {
        return false;
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

void UdpIngress::DetachNativeJob(ClientSession& session) noexcept {
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

void UdpIngress::RetireNativeJob(ClientSession& session) noexcept {
    DetachNativeJob(session);
    session.impl_->job_pin.reset();
    session.impl_->request.reset();
}

void UdpIngress::RegisterNativeJob(const ClientSessionPtr& session) {
    auto& job = *session->impl_;
    job.owner = this;
    job.job_registered = true;
    job.job_pin = session;
    job.job_previous = nullptr;
    job.job_next = impl_->jobs;
    job.job_linked = true;
    if (impl_->jobs) impl_->jobs->impl_->job_previous = session.get();
    impl_->jobs = session.get();
    ++impl_->outstanding_jobs;
}

// One run per association. Admission happens before the first Dispatch;
// packets arriving meanwhile wait in the bounded association queue, and a
// rejection closes the association, dropping them. The frame owns the
// connection reservations and the online-device guard until it ends.
net::awaitable<void> UdpIngress::RunNativeDispatch(ClientSessionPtr client_session) {
    auto& job = *client_session->impl_;
    auto& request = *job.request;
    if (request.active_sessions) ++*request.active_sessions;
    auto active_guard = MakeScopeExit([active = request.active_sessions]() noexcept {
        if (active) --*active;
    });
    request.stats->OnConnectionAccepted();
    auto connection_stats = MakeScopeExit([stats = request.stats]() noexcept {
        stats->OnConnectionClosed();
    });
    std::optional<NativeAssociationAdmission> admission;
    try {
        admission = co_await AdmitNativeAssociation(
            request.context, request.profile, request.tracker, request.limiter,
            *request.stats);
        request.profile = {};
        request.tracker = nullptr;
        request.tracker_owner.reset();
        if (!admission || client_session->Closed()) {
            client_session->Close();
            co_return;
        }
        RelayResult result = co_await request.dispatcher->Dispatch(
            *request.io_context, request.policy, nullptr,
            transport::Link{client_session.get(), client_session.get()},
            InitialPayload{}, request.context, *request.stats, request.timeouts);
        if (result.error != ErrorCode::OK) {
            LOG_CONN_DEBUG(request.context,
                "UDP dispatcher ended > {} up={}B down={}B",
                ErrorCodeToString(result.error), result.bytes_up,
                result.bytes_down);
        }
    } catch (const IoSystemError& error) {
        if (error.code() != net::error::operation_aborted && error.code() != net::error::eof) {
            LOG_CONN_ERROR(request.context, "UDP dispatcher failed worker={} > {}",
                           request.worker_id, error.what());
        }
    } catch (const std::exception& e) {
        LOG_CONN_ERROR(request.context, "UDP dispatcher coroutine failed worker={} > {}",
                  request.worker_id, e.what());
    } catch (...) {
        LOG_CONN_ERROR(request.context, "UDP dispatcher coroutine failed worker={} > unknown error",
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
    if (!datagram.environment && !datagram.dispatcher) {
        return;
    }
    if (!datagram.receiver) {
        LOG_NET_DEBUG(
            "UDP datagram rejected worker={} tag={} > missing prepared receiver",
            datagram.worker_id,
            impl_->tag);
        return;
    }

    const std::string_view socket_key = datagram.socket_key;
    const auto socket = impl_->udp_sockets.find(socket_key);
    if (socket == impl_->udp_sockets.end() || socket->second.socket.get() != datagram.sock) return;
    const auto now = std::chrono::steady_clock::now();

    const auto normalized_client_addr =
        iputil::NormalizeAddress(datagram.client_endpoint.address());
    auto decoded = impl_->proxy->Process(InboundDatagramRequest{
        .tag = impl_->tag,
        .payload = datagram.payload,
        .associations = datagram.environment ? &socket->second.associations : nullptr,
        .configuration = datagram.environment && datagram.environment->prepared
            ? datagram.environment->prepared->settings.get() : nullptr,
        .worker_id = datagram.worker_id,
        .client_endpoint = datagram.client_endpoint,
    });
    if (!decoded) {
        if (decoded.error() == ErrorCode::PROTOCOL_AUTH_FAILED) {
            // Datagram sources are socket peers, never PROXY protocol clients,
            // so a credential failure is logged without feeding the ban table.
            session::Context rejected;
            rejected.worker_id = datagram.worker_id;
            rejected.inbound.tag = impl_->tag;
            rejected.inbound.source_addr = normalized_client_addr;
            rejected.inbound.source_ip = iputil::AddressText(normalized_client_addr).View();
            rejected.inbound.source_port = datagram.client_endpoint.port();
            rejected.content.network = Network::UDP;
            ::proxy::LogInboundAuthFailure(
                rejected, "datagram authentication or validation failed");
        }
        return;
    }
    if (!buf::SetUdpTarget(decoded->payload, decoded->target)) return;
    if (datagram.environment && decoded->association_policy &&
        decoded->session_id && decoded->packet_id) {
        if (!datagram.environment->prepared || !datagram.environment->prepared->settings) return;
        if (decoded->committed_association) {
            const ClientSessionKey key{decoded->session_owner, decoded->session_id, {},
                                       datagram.environment->prepared->settings.get()};
            if (auto outer = impl_->client_sessions.find(socket_key);
                outer != impl_->client_sessions.end()) {
                auto row = outer->second.find(key);
                if (row != outer->second.end() && row->second.link) {
                    auto session = row->second.link;
                    auto& state = *session->impl_;
                    if (state.handoff_record && !session->Closed() &&
                        state.handoff_record->association.get() == decoded->committed_association) {
                        row->second.last_active = now;
                        session->UpdateReplyEndpoint(datagram.client_endpoint);
                        (void)session->Push(decoded->target, std::move(decoded->payload));
                    }
                }
            }
            return;
        }
        if (!decoded->user || !datagram.environment->prepared ||
            !datagram.environment->prepared->settings) return;
        UdpHandoffIdentity identity{
            std::string(socket_key), std::string(impl_->tag),
            datagram.environment->prepared->settings.get(),
            ClientSessionKey{decoded->session_owner, decoded->session_id, {},
                             datagram.environment->prepared->settings.get()}};
        auto record = impl_->directory.Claim(
            identity, datagram.environment->prepared->settings, *decoded->association_policy);
        if (!record) return;
        auto release_claim = MakeScopeExit([record]() noexcept {
            record->association->claimed = false;
        });
        if (auto session = record->session.lock()) {
            if (session->Closed() ||
                !record->association->Check(*decoded->packet_id, datagram.worker_id,
                    datagram.client_endpoint, InboundDatagramCheck::Commit)) {
                return;
            }
            session->UpdateReplyEndpoint(datagram.client_endpoint);
            if (auto* hook = session->impl_->association_hook) {
                auto outer = impl_->client_sessions.find(hook->socket_key);
                if (outer != impl_->client_sessions.end()) {
                    auto row = outer->second.find(*hook->client_key);
                    if (row != outer->second.end()) row->second.last_active = now;
                }
            }
            (void)session->Push(decoded->target, std::move(decoded->payload));
            return;
        }
        if (!record->association->Check(*decoded->packet_id, datagram.worker_id,
                datagram.client_endpoint, InboundDatagramCheck::Commit)) {
            return;
        }
        ProcessDecoded(datagram, std::move(*decoded), std::move(record));
        return;
    }
    ProcessDecoded(datagram, std::move(*decoded));
}

void UdpIngress::ProcessDecoded(const UdpDatagramContext& datagram,
    InboundDatagramResult result, std::shared_ptr<UdpHandoffRecord> record) {
    auto* decoded = &result;
    const auto socket_key = datagram.socket_key;
    const auto now = std::chrono::steady_clock::now();
    const auto normalized_client_addr = iputil::NormalizeAddress(datagram.client_endpoint.address());

    auto client_key_log = [&]() {
        return TargetAddress(normalized_client_addr, datagram.client_endpoint.port());
    };
    const ClientSessionKey client_session_key{
        decoded->session_owner, decoded->session_id, datagram.client_endpoint,
        datagram.environment && datagram.environment->prepared
            ? datagram.environment->prepared->settings.get() : nullptr};
    if (decoded->session_owner.size == 0) {
        LOG_NET_DEBUG(
            "UDP datagram rejected worker={} client={} > missing authenticated session owner",
            datagram.worker_id,
            client_key_log());
        return;
    }

    ClientSessionPtr current_session;
    if (auto outer = impl_->client_sessions.find(socket_key);
        outer != impl_->client_sessions.end()) {
        if (auto row = outer->second.find(client_session_key);
            row != outer->second.end()) {
            if (ShouldReclaim(
                    row->second, now, row->second.reclaim_hook.idle_timeout)) {
                ReclaimAssociation(row->second.reclaim_hook, now);
                // Synchronous cancellation may retire or replace the listener.
                // The decoded packet cannot create a request for its old socket.
                if (!OwnsSocket(socket_key, datagram.sock)) return;
            } else if (row->second.link && !row->second.link->Closed()) {
                current_session = row->second.link;
                if (current_session->Owns(decoded->session_owner)) {
                    row->second.last_active = now;
                }
            }
        }
    }
    const bool need_new_session = !current_session;
    ClientSessionPtr packet_session = current_session;
    ClientSessionPtr preparation_session;
    auto preparation_guard = MakeScopeExit([&]() noexcept {
        if (preparation_session) preparation_session->Close();
    });

    if (need_new_session) {
        if (!decoded->user) {
            LOG_NET_DEBUG(
                "UDP datagram rejected worker={} client={} > missing authenticated user",
                datagram.worker_id,
                client_key_log());
            return;
        }
        auto response = impl_->proxy->CreateDatagramResponse(*decoded);
        if (!response || !*response) {
            LOG_NET_DEBUG("UDP response preparation failed worker={} client={}",
                          datagram.worker_id, client_key_log());
            return;
        }

        const auto sock_it = impl_->udp_sockets.find(socket_key);
        if (sock_it == impl_->udp_sockets.end() ||
            sock_it->second.socket.get() != datagram.sock ||
            impl_->state != Impl::State::Running) {
            return;
        }
        auto stable_socket = sock_it->second.socket;
        // Copied out: session creation may re-enter CloseSocket and erase the row.
        const auto local_endpoint = sock_it->second.local_endpoint;

        const uint32_t worker_id = datagram.worker_id;
        ReplyRoute reply{
            .socket_key = memory::ThreadLocalString{socket_key},
            .socket = stable_socket,
            .response = std::move(*response),
            .sink = &datagram.reply_sink,
            .worker_id = worker_id};
        auto client_session = CreateClientSession(
            socket_key, client_session_key, datagram.io_context,
            std::move(reply), datagram.client_endpoint,
            decoded->session_owner, now, datagram.timeouts.IdleTimeout());
        if (!client_session) return;
        packet_session = client_session;
        preparation_session = client_session;
        if (impl_->state != Impl::State::Running ||
            !OwnsSocket(socket_key, stable_socket.get())) {
            client_session->Close();
            return;
        }
        auto& session_impl = *client_session->impl_;
        session_impl.owner = this;
        session_impl.handoff_record = record;
        if (datagram.environment && record) {
            record->session = client_session;
            auto socket = impl_->udp_sockets.find(socket_key);
            if (socket == impl_->udp_sockets.end() ||
                socket->second.socket.get() != datagram.sock) return;
            socket->second.associations.insert_or_assign(
                InboundDatagramAssociationKey{decoded->session_owner, *decoded->session_id,
                    client_session_key.configuration},
                record->association.get());
        }
        session_impl.request.emplace(datagram.receiver->dispatch_policy);
        auto& request = *session_impl.request;
        auto& ctx = request.context;
        ctx.conn_id = session::NewID(datagram.worker_id);
        ctx.worker_id = datagram.worker_id;
        const std::string_view inbound_tag = datagram.receiver->inbound_tag.empty()
            ? std::string_view(impl_->tag)
            : std::string_view(datagram.receiver->inbound_tag);
        ctx.inbound.tag.assign(inbound_tag);
        ctx.inbound.accounting_key.assign(datagram.receiver->accounting_key);
        if (const auto* route_tags = datagram.receiver->RouteInboundTags()) {
            ctx.inbound.tags.reserve(route_tags->size());
            for (const auto& route_tag : *route_tags)
                ctx.inbound.tags.emplace_back(route_tag);
        }
        const iputil::AddressText client_ip(normalized_client_addr);
        ctx.inbound.source_ip.assign(client_ip.View());
        ctx.inbound.source_addr = normalized_client_addr;
        ctx.inbound.source_port = datagram.client_endpoint.port();
        ctx.inbound.local_endpoint = local_endpoint;
        request.profile = *decoded->user;
        if (datagram.environment) {
            const auto& env = *datagram.environment;
            request.dispatcher = env.dispatcher;
            request.stats = env.stats;
            request.limiter = env.limiter;
            request.tracker_owner = std::move(decoded->tracker);
            request.tracker = env.tracker ? env.tracker : request.tracker_owner.get();
            request.active_sessions = env.active_sessions;
        } else {
            request.dispatcher = datagram.dispatcher;
            request.stats = &datagram.stats;
            request.limiter = decoded->limiter;
            request.tracker_owner = std::move(decoded->tracker);
            request.tracker = request.tracker_owner.get();
        }
        ::proxy::BindAuthenticatedInbound(
            ctx, request.profile,
            ::proxy::InboundRequestTarget{
                Network::UDP,
                decoded->target,
                std::move(decoded->forwarded)});
        request.io_context = &datagram.io_context;
        request.timeouts = datagram.timeouts;
        request.worker_id = worker_id;
        if (!packet_session->Push(decoded->target, std::move(decoded->payload))) {
            LOG_NET_DEBUG("UDP link enqueue failed worker={} client={}",
                          datagram.worker_id, client_key_log());
            return;
        }
        RegisterNativeJob(client_session);
        try {
            net::co_spawn(
                datagram.io_context.get_executor(),
                RunNativeDispatch(client_session),
                [client_session, worker_id](std::exception_ptr error) {
                    client_session->Close();
                    client_session->impl_->owner->RetireNativeJob(*client_session);
                    if (error) {
                        try {
                            try { std::rethrow_exception(error); }
                            catch (const IoSystemError& failure) {
                                if (failure.code() != net::error::operation_aborted &&
                                    failure.code() != net::error::eof)
                                    LOG_ERROR("UDP completion failed worker={} > {}", worker_id, failure.what());
                            } catch (const std::exception& failure) {
                                LOG_ERROR("UDP completion failed worker={} > {}", worker_id, failure.what());
                            } catch (...) {
                                LOG_ERROR("UDP completion failed worker={} > unknown error", worker_id);
                            }
                        } catch (...) {} // Completion cleanup must survive logging allocation failures.
                    }
                });
        } catch (...) {
            RetireNativeJob(*client_session);
            client_session->Close();
            throw;
        }
        preparation_session.reset();
        preparation_guard.Release();
        return;
    }

    if (!packet_session || packet_session->Closed() ||
        !packet_session->Owns(decoded->session_owner)) {
        decoded->payload.clear();
        return;
    }
    // `last_active` was already updated during the initial lookup.
    packet_session->UpdateReplyEndpoint(datagram.client_endpoint);
    if (!packet_session->Push(decoded->target, std::move(decoded->payload))) {
        LOG_NET_DEBUG("UDP link enqueue failed worker={} client={}",
                         datagram.worker_id, client_key_log());
    }
}

UdpIngress::ReplyEnqueueResult UdpIngress::EnqueueReply(
    std::string_view socket_key,
    udp::endpoint endpoint,
    buf::MultiBuffer payload) {
    const size_t payload_size = payload.byte_size();
    if (payload_size == 0 || payload_size > kMaxQueuedUdpBytes) {
        return ReplyEnqueueResult::Rejected;
    }
    if (auto it = impl_->reply_queues.find(socket_key);
        it != impl_->reply_queues.end() &&
        WouldOverflowUdpQueue(it->second, payload_size)) {
        return ReplyEnqueueResult::Rejected;
    }
    auto reservation = impl_->budget.ReservePayload(payload);
    if (!reservation) return ReplyEnqueueResult::Rejected;

    auto [queue_it, inserted] = FindOrEmplaceStringKey(
        impl_->reply_queues, socket_key);
    (void)inserted;
    auto& queue = queue_it->second;
    const bool should_start_send = queue.active_id == 0;

    PendingUdpReply reply;
    reply.endpoint = std::move(endpoint);
    reply.payload_size = payload_size;
    reply.reservation = std::move(reservation);
    reply.payload = std::move(payload);
    queue.pending.push_back(std::move(reply));
    queue.queued_bytes += payload_size;
    return should_start_send
        ? ReplyEnqueueResult::StartSend
        : ReplyEnqueueResult::Queued;
}

std::optional<UdpIngress::PendingUdpReply>
UdpIngress::BeginReplySend(std::string_view socket_key) {
    auto it = impl_->reply_queues.find(socket_key);
    if (it == impl_->reply_queues.end()) return std::nullopt;
    return impl_->BeginReplySend(it->second);
}

std::optional<UdpIngress::PendingUdpReply>
UdpIngress::CompleteReplySend(
    std::string_view socket_key,
    uint64_t completed_id) {
    auto it = impl_->reply_queues.find(socket_key);
    if (it == impl_->reply_queues.end()) {
        return std::nullopt;
    }

    auto& queue = it->second;
    if (completed_id == 0 || queue.active_id != completed_id) {
        return std::nullopt;
    }
    queue.active_id = 0;
    queue.active_payload_size = 0;
    return impl_->BeginReplySend(queue);
}

void UdpIngress::ClearReplyQueue(std::string_view socket_key) {
    const auto it = impl_->reply_queues.find(socket_key);
    if (it != impl_->reply_queues.end()) {
        impl_->reply_queues.erase(it);
    }
    MaybeShrinkHashContainer(impl_->reply_queues, 8);
}

UdpIngress::ClientSessionPtr UdpIngress::CreateClientSession(
    std::string_view socket_key,
    const ClientSessionKey& client_key,
    net::io_context& io_context,
    ReplyRoute reply,
    udp::endpoint reply_endpoint,
    InboundDatagramOwner session_owner,
    std::chrono::steady_clock::time_point last_active,
    std::chrono::seconds idle_timeout) {
    if (impl_->state != Impl::State::Running) return nullptr;
    if (client_key.owner.size == 0 || !client_key.owner.Same(session_owner)) return nullptr;
    auto association = impl_->budget.AcquireAssociation();
    if (!association) return nullptr;
    auto session = memory::AllocateShared<ClientSession>(
        io_context,
        std::move(reply),
        std::move(reply_endpoint),
        std::move(session_owner), impl_->budget, std::move(association));
    impl_->reclaimer.ReserveRow();
    auto [sessions_it, group_inserted] = FindOrEmplaceStringKey(
        impl_->client_sessions, socket_key);
    auto& sessions = sessions_it->second;
    auto session_it = sessions.find(client_key);
    if (session_it == sessions.end()) {
        try {
            auto [inserted_it, inserted] = sessions.try_emplace(
                client_key,
                UdpClientSession{.link = session, .last_active = last_active, .reclaim_hook = {}});
            if (inserted) {
                impl_->Link(*this, inserted_it->second, sessions_it->first, inserted_it->first,
                            idle_timeout);
            }
        } catch (...) {
            if (group_inserted) impl_->client_sessions.erase(sessions_it);
            throw;
        }
    } else {
        auto& row = session_it->second;
        // The replaced session's closure must not mark the reused row due.
        auto previous = std::move(row.link);
        if (previous) previous->impl_->association_hook = nullptr;
        impl_->SetLocalAssociation(row.reclaim_hook, nullptr);
        row.link = session;
        row.last_active = last_active;
        row.reclaim_hook.idle_timeout = idle_timeout;
        session->impl_->association_hook = &row.reclaim_hook;
        impl_->reclaimer.Rearm(row.reclaim_hook, UdpAssociationExpiry(last_active, idle_timeout));
        // Close may synchronously call CloseSocket and erase this replacement.
        // Do not access map iterators or key views after invoking it.
        if (previous) previous->Close();
    }
    return session;
}

void UdpIngress::ReclaimAssociation(
    UdpAssociationHook& hook,
    std::chrono::steady_clock::time_point now) noexcept {
    auto outer = impl_->client_sessions.find(hook.socket_key);
    if (outer == impl_->client_sessions.end()) {
        impl_->reclaimer.Unregister(hook);
        return;
    }
    auto row = outer->second.find(*hook.client_key);
    if (row == outer->second.end() || &row->second.reclaim_hook != &hook) {
        impl_->reclaimer.Unregister(hook);
        return;
    }
    if (!ShouldReclaim(row->second, now, hook.idle_timeout)) {
        // Uplink activity moved last_active without touching the heap.
        impl_->reclaimer.Rearm(hook, UdpAssociationExpiry(row->second.last_active,
                                                          hook.idle_timeout));
        return;
    }
    auto session = row->second.link;
    const bool idle = session && !session->Closed() &&
        hook.idle_timeout.count() > 0 &&
        now - row->second.last_active > hook.idle_timeout;
    impl_->Unlink(row->second);
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
        impl_->Unlink(session);
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
    std::string_view socket_key,
    SocketPtr socket) {
    if (!socket || impl_->state != Impl::State::Running) {
        return nullptr;
    }
    if (impl_->udp_sockets.find(socket_key) != impl_->udp_sockets.end()) {
        return nullptr;
    }
    std::optional<tcp::endpoint> local_endpoint;
    IoErrorCode local_ec;
    const auto local_ep = socket->local_endpoint(local_ec);
    if (!local_ec && !local_ep.address().is_unspecified()) {
        local_endpoint.emplace(iputil::NormalizeAddress(local_ep.address()), local_ep.port());
    }
    impl_->udp_sockets.try_emplace(
        memory::ThreadLocalString{socket_key},
        Impl::BoundSocket{
            .socket = socket,
            .local_endpoint = std::move(local_endpoint),
            .associations = {}});
    return socket;
}

UdpIngress::SocketPtr UdpIngress::FindSocket(
    std::string_view socket_key) noexcept {
    auto it = impl_->udp_sockets.find(socket_key);
    return it == impl_->udp_sockets.end() ? nullptr : it->second.socket;
}

bool UdpIngress::OwnsSocket(
    std::string_view socket_key,
    const udp::socket* socket) const noexcept {
    auto it = impl_->udp_sockets.find(socket_key);
    return socket && it != impl_->udp_sockets.end() &&
        it->second.socket.get() == socket;
}

size_t UdpIngress::SocketCount() const noexcept {
    return impl_->udp_sockets.size();
}

void UdpIngress::CloseSocket(std::string_view socket_key) noexcept {
    // Find in every independent table before extraction can invalidate a key
    // view borrowed from any one of those tables.
    auto sessions_it = impl_->client_sessions.find(socket_key);
    auto reply_it = impl_->reply_queues.find(socket_key);
    auto sock_it = impl_->udp_sockets.find(socket_key);
    SocketPtr socket_identity = sock_it == impl_->udp_sockets.end()
        ? SocketPtr{} : sock_it->second.socket;

    ClientSession* notify = nullptr;
    for (auto* job = impl_->jobs; job;) {
        auto* next = job->impl_->job_next;
        if (socket_identity && job->impl_->reply.socket == socket_identity) {
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
            impl_->Unlink(session);
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
        : std::move(detached_socket.mapped().socket);
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

}  // namespace worker_detail
