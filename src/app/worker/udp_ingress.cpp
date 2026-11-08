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

void UdpReplyFence::Lease::Reset() noexcept {
    if (!fence_) return;
    if (--fence_->pending_ == 0) {
        try { (void)fence_->drained_.try_send(IoErrorCode{}); }
        catch (...) { FailRuntime("udp-reply", "failed to signal association reply drain"); }
    }
    fence_.reset();
}

net::awaitable<void> UdpReplyFence::AsyncDrain() {
    while (pending_ != 0) {
        auto [ec] = co_await drained_.async_receive(net::as_tuple(net::use_awaitable));
        if (ec) throw IoSystemError(ec);
    }
}

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
    memory::ScopedWorkerAllocation reply_allocation;
    auto payload = response->Encode(packet);
    if (payload.empty()) return false;
    return sink->EnqueueUdpReply(socket_key, socket.get(), endpoint, std::move(payload), worker_id, fence);
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
        // Owned only by standalone dispatcher fixtures; production uses capabilities.
        std::shared_ptr<UserOnlineTracker> tracker;
        ConnectionLimiter* limiter = nullptr;
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
    std::shared_ptr<app::PhysicalSessionCapabilities> capabilities;
    std::shared_ptr<app::PhysicalSessionRegistry> registry;
    std::shared_ptr<app::PhysicalSessionRecord> registration;
    std::shared_ptr<ExecutionDomain> domain;
    std::shared_ptr<UdpHandoffRecord> handoff_record;
    UdpIngress* owner = nullptr;
    UdpIngress* destination = nullptr;
    std::optional<ReplyRoute> next_reply;
    UdpResourceBudget::AssociationLease next_association;
    std::vector<UdpResourceBudget::PayloadReservation> next_payloads;
    bool source_detached = false;
    bool target_reserved = false;
    std::optional<ClientSessionKey> transfer_key;
    std::string transfer_socket_key;
    std::chrono::steady_clock::time_point transfer_activity;
    std::chrono::seconds transfer_idle{0};
    net::any_io_executor source_executor;
    bool source_control = false;
    bool close_requested = false;
    bool transferring = false;
    bool close_pending = false;
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
    return impl_->closed || impl_->close_requested || impl_->close_pending;
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
    ClientSession* jobs = nullptr;
    size_t outstanding_jobs = 0;
    size_t join_observers = 0;
    uint64_t last_reply_id = 0;
    State state = State::Running;
    size_t controls = 0;

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

net::awaitable<void> UdpIngress::ClientSession::PrepareHandoff(
    const ExecutionDomain::HandoffTarget& target) {
    auto& state = *impl_;
    if (Closed() || !state.destination || !state.next_reply || !state.association_hook)
        throw IoSystemError(net::error::operation_aborted);
    state.transferring = true;
    state.source_executor = state.domain->CurrentTarget().executor;
    ++state.owner->impl_->controls;
    state.source_control = true;
    const auto* hook = state.association_hook;
    state.transfer_key = *hook->client_key;
    state.transfer_socket_key.assign(hook->socket_key);
    state.transfer_idle = hook->idle_timeout;
    auto source_outer = state.owner->impl_->client_sessions.find(hook->socket_key);
    auto source_row = source_outer->second.find(*hook->client_key);
    state.transfer_activity = source_row->second.last_active;
    if (state.reply.fence) co_await state.reply.fence->AsyncDrain();
    if (state.close_pending || !state.association_hook)
        throw IoSystemError(net::error::operation_aborted);
    auto reserve_target = [this]() -> net::awaitable<void> {
        memory::ScopedWorkerAllocation worker_allocation;
        auto& transfer = *impl_;
        auto& destination = *transfer.destination->impl_;
        if (destination.state != UdpIngress::Impl::State::Running ||
            !transfer.destination->OwnsSocket(transfer.next_reply->socket_key,
                                              transfer.next_reply->socket.get()))
            throw IoSystemError(net::error::operation_aborted);
        transfer.next_association = destination.budget.AcquireAssociation();
        if (!transfer.next_association) throw IoSystemError(net::error::no_buffer_space);
        transfer.next_payloads.reserve(transfer.input_queue.size());
        for (size_t index = 0; index < transfer.input_queue.size(); ++index) {
            auto reservation = destination.budget.ReservePayload(transfer.input_queue[index].payload);
            if (!reservation) throw IoSystemError(net::error::no_buffer_space);
            transfer.next_payloads.push_back(std::move(reservation));
        }
        destination.reclaimer.ReserveRow();
        auto [outer, inserted_outer] = FindOrEmplaceStringKey(
            destination.client_sessions, transfer.next_reply->socket_key);
        (void)inserted_outer;
        try {
            auto [row, inserted] = outer->second.try_emplace(*transfer.transfer_key,
                UdpClientSession{.link = {}, .last_active = transfer.transfer_activity, .reclaim_hook = {}});
            if (!inserted) throw IoSystemError(net::error::already_started);
            const auto& key = *transfer.transfer_key;
            if (key.session_id.has_value()) {
                auto socket = destination.udp_sockets.find(transfer.next_reply->socket_key);
                try {
                    socket->second.associations.try_emplace(
                        InboundDatagramAssociationKey{key.owner, *key.session_id, key.configuration}, nullptr);
                } catch (...) {
                    outer->second.erase(row);
                    throw;
                }
            }
            destination.reclaimer.Register(row->second.reclaim_hook, *transfer.destination,
                outer->first, row->first, transfer.transfer_idle,
                UdpAssociationHook::TimePoint::max());
            transfer.target_reserved = true;
        } catch (...) {
            if (outer->second.empty()) destination.client_sessions.erase(outer);
            throw;
        }
        co_return;
    };
    co_await net::co_spawn(target.executor, reserve_target(), net::use_awaitable);
    if (state.close_pending || !state.association_hook)
        throw IoSystemError(net::error::operation_aborted);
    source_outer = state.owner->impl_->client_sessions.find(state.reply.socket_key);
    source_row = source_outer->second.find(*state.transfer_key);
    // Keep a capacity-reserved, inert source row until commit/cancel. Rollback
    // can restore it without allocating under memory pressure.
    state.owner->impl_->SetLocalAssociation(source_row->second.reclaim_hook, nullptr);
    state.association_hook = nullptr;
    source_row->second.link.reset();
    state.owner->impl_->reclaimer.Rearm(source_row->second.reclaim_hook,
                                       UdpAssociationHook::TimePoint::max());
    state.source_detached = true;
    state.owner->DetachNativeJob(*this);
}

void UdpIngress::ClientSession::CommitHandoff(
    const ExecutionDomain::HandoffTarget& target) noexcept {
    memory::ScopedWorkerAllocation worker_allocation;
    auto& state = *impl_;
    auto* source = state.owner;
    auto* destination = state.destination;
    auto pin = state.job_pin.lock();
    if (!pin || !state.source_detached) FailRuntime("udp-handoff", "missing prepared association");
    auto outer = destination->impl_->client_sessions.find(state.next_reply->socket_key);
    if (outer != destination->impl_->client_sessions.end()) {
        auto row = outer->second.find(*state.transfer_key);
        if (row != outer->second.end() && !row->second.link) {
            row->second.link = pin;
            row->second.last_active = state.transfer_activity;
            state.association_hook = &row->second.reclaim_hook;
            destination->impl_->SetLocalAssociation(
                row->second.reclaim_hook, state.handoff_record->association.get());
            destination->impl_->reclaimer.Rearm(row->second.reclaim_hook,
                UdpAssociationExpiry(state.transfer_activity, state.transfer_idle));
        }
    }
    state.association = std::move(state.next_association);
    for (size_t index = 0; index < state.input_queue.size(); ++index)
        state.input_queue[index].reservation = std::move(state.next_payloads[index]);
    state.next_payloads.clear();
    state.budget = &destination->impl_->budget;
    state.reply = std::move(*state.next_reply);
    state.next_reply.reset();
    state.source_detached = false;
    state.target_reserved = false;
    destination->RegisterNativeJob(pin);
    state.request->worker_id = target.worker_id;
    state.request->context.worker_id = target.worker_id;
    state.request->io_context = target.reactor;
    state.destination = nullptr;
    state.transferring = false;
    state.source_control = false;
    try {
        net::post(state.source_executor,
            [source, socket_key = std::move(state.transfer_socket_key), key = *state.transfer_key] {
                auto outer = source->impl_->client_sessions.find(socket_key);
                if (outer != source->impl_->client_sessions.end()) {
                    auto row = outer->second.find(key);
                    if (row != outer->second.end() && !row->second.link) {
                        source->impl_->Unlink(row->second);
                        outer->second.erase(row);
                    }
                    if (outer->second.empty()) source->impl_->client_sessions.erase(outer);
                }
                source->ReleaseControl();
            });
    } catch (...) {
        FailRuntime("udp-handoff", "failed to post source handoff cleanup");
    }
    if (state.close_pending || !state.association_hook ||
        destination->impl_->state != UdpIngress::Impl::State::Running)
        CloseWithError(state.terminal_error);
}

net::awaitable<void> UdpIngress::ClientSession::CancelHandoff(
    const ExecutionDomain::HandoffTarget&) {
    auto& state = *impl_;
    if (!state.transferring) {
        state.destination = nullptr;
        state.next_reply.reset();
        co_return;
    }
    if (state.destination && state.next_reply && state.transfer_key) {
        auto cleanup_target = [this]() -> net::awaitable<void> {
            memory::ScopedWorkerAllocation worker_allocation;
            auto& transfer = *impl_;
            auto& destination = *transfer.destination->impl_;
            auto outer = destination.client_sessions.find(transfer.next_reply->socket_key);
            if (transfer.target_reserved && outer != destination.client_sessions.end()) {
                auto row = outer->second.find(*transfer.transfer_key);
                if (row != outer->second.end() && !row->second.link) {
                    destination.Unlink(row->second);
                    outer->second.erase(row);
                }
                if (outer->second.empty()) destination.client_sessions.erase(outer);
            }
            transfer.target_reserved = false;
            transfer.next_payloads.clear();
            transfer.next_association = {};
            transfer.next_reply.reset();
            co_return;
        };
        co_await net::co_spawn(state.destination->impl_->completion_signal.get_executor(),
                              cleanup_target(), net::use_awaitable);
    }
    state.next_reply.reset();
    state.transfer_socket_key.clear();
    if (state.source_detached) {
        auto outer = state.owner->impl_->client_sessions.find(state.reply.socket_key);
        if (state.owner->impl_->state == UdpIngress::Impl::State::Running &&
            outer != state.owner->impl_->client_sessions.end()) {
            auto row = outer->second.find(*state.transfer_key);
            if (row != outer->second.end() && !row->second.link) {
                row->second.link = state.job_pin.lock();
                state.association_hook = &row->second.reclaim_hook;
                state.owner->impl_->SetLocalAssociation(
                    row->second.reclaim_hook, state.handoff_record->association.get());
                state.owner->impl_->reclaimer.Rearm(row->second.reclaim_hook,
                    UdpAssociationExpiry(state.transfer_activity, state.transfer_idle));
            }
        }
        if (!state.association_hook) state.close_pending = true;
        state.source_detached = false;
        state.owner->RegisterNativeJob(state.job_pin.lock());
    }
    state.destination = nullptr;
    state.transferring = false;
    if (state.source_control) {
        state.source_control = false;
        state.owner->ReleaseControl();
    }
    if (state.close_pending) CloseWithError(state.terminal_error);
}

void UdpIngress::ClientSession::CloseWithError(ErrorCode error) noexcept {
    memory::ScopedWorkerAllocation worker_allocation;
    if (impl_->transferring) {
        impl_->close_pending = true;
        impl_->terminal_error = error;
        return;
    }
    if (impl_->domain && impl_->job_registered &&
        ExecutionDomain::Current().get() != impl_->domain.get()) {
        if (impl_->close_requested) return;
        impl_->close_requested = true;
        auto pin = impl_->job_pin.lock();
        if (!pin) FailRuntime("udp-ingress", "missing native close owner");
        try {
            impl_->domain->Execute([pin = std::move(pin), error] {
                pin->CloseWithError(error);
            });
        } catch (...) {
            FailRuntime("udp-ingress", "failed to enqueue native close");
        }
        return;
    }
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
    if (impl_->outstanding_jobs != 0 || impl_->controls != 0) {
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
    if (impl_->outstanding_jobs == 0 && impl_->controls == 0) impl_->state = Impl::State::Drained;
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
            while (impl_->outstanding_jobs != 0 || impl_->controls != 0) {
                auto [ec] = co_await impl_->completion_signal.async_receive(
                    net::as_tuple(asio::bind_cancellation_slot(
                        asio::cancellation_slot{}, net::use_awaitable)));
                if (ec && (impl_->outstanding_jobs != 0 || impl_->controls != 0))
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
    if (impl_->state == Impl::State::Stopping && impl_->outstanding_jobs == 0 && impl_->controls == 0)
        impl_->state = Impl::State::Drained;
    if (impl_->join_observers != 0 && impl_->outstanding_jobs == 0 && impl_->controls == 0) {
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

void UdpIngress::ReleaseControl() noexcept {
    if (impl_->controls == 0) FailRuntime("udp-ingress", "control count underflow");
    --impl_->controls;
    if (impl_->controls == 0 && impl_->outstanding_jobs == 0 && impl_->join_observers) {
        try { (void)impl_->completion_signal.try_send(IoErrorCode{}); }
        catch (...) { FailRuntime("udp-ingress", "failed to signal control drain"); }
    }
}

// One run per association. Admission happens before the first Dispatch;
// packets arriving meanwhile wait in the bounded association queue, and a
// rejection closes the association, dropping them. The frame owns the
// connection reservations and the online-device guard until it ends.
net::awaitable<void> UdpIngress::RunNativeFlow(ClientSessionPtr client_session) {
    auto& state = *client_session->impl_;
    std::exception_ptr failure;
    try {
        co_await state.capabilities->ProcessNativeDatagram(
            transport::Link{client_session.get(), client_session.get()},
            state.request->profile, state.request->context);
    } catch (...) { failure = std::current_exception(); }
    client_session->Close();
    // The borrowed structured task group is still alive in this child.
    state.capabilities->RequestStop();
    if (failure) std::rethrow_exception(failure);
}

net::awaitable<void> UdpIngress::RunNativeDispatch(ClientSessionPtr client_session) {
    auto& job = *client_session->impl_;
    auto& request = *job.request;
    if (job.capabilities) {
        if (job.registry) {
            memory::ScopedWorkerAllocation registration_allocation;
            job.registration = job.registry->Register(job.capabilities, job.domain);
            job.registration->conn_id = request.context.conn_id;
        }
        std::exception_ptr failure;
        try {
            co_await RunAwaitableTaskGroup(job.domain->Executor(),
                [client_session](AwaitableTaskGroup& tasks) {
                    auto& state = *client_session->impl_;
                    state.capabilities->Initialize(state.domain->Reactor(), tasks);
                    state.domain->RegisterResource(*client_session);
                    if (state.registration)
                        state.registration->initialized.store(true, std::memory_order_release);
                    tasks.Spawn(RunNativeFlow(client_session));
                });
        } catch (...) { failure = std::current_exception(); }
        client_session->Close();
        job.domain->UnregisterResource(*client_session);
        try { co_await job.capabilities->AsyncJoin(); }
        catch (...) { if (!failure) failure = std::current_exception(); }
        if (job.registration) {
            try { co_await job.registry->Retire(std::move(job.registration)); }
            catch (...) { if (!failure) failure = std::current_exception(); }
        }
        job.capabilities.reset();
        if (failure) std::rethrow_exception(failure);
        co_return;
    }
    request.stats->OnConnectionAccepted();
    auto connection_stats = MakeScopeExit([stats = request.stats]() noexcept {
        stats->OnConnectionClosed();
    });
    std::optional<NativeAssociationAdmission> admission;
    try {
        admission = co_await AdmitNativeAssociation(
            request.context, request.profile, request.tracker.get(), request.limiter,
            *request.stats);
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

struct UdpIngress::AuthenticatedPacket {
    AuthenticatedPacket(const UdpDatagramContext& source, InboundDatagramResult result,
                        std::shared_ptr<InboundDatagramResponse> response_value,
                        UdpResourceBudget::PayloadReservation reservation_value,
                        SocketPtr socket_value)
        : socket_key(source.socket_key), socket(std::move(socket_value)),
          environment(*source.environment),
          context(source), decoded(std::move(result)), profile(*decoded.user),
          response(std::move(response_value)), reservation(std::move(reservation_value)) {
        context.socket_key = socket_key;
        context.sock = socket.get();
        context.payload = {};
        context.environment = &environment;
        context.receiver = environment.receiver.get();
        decoded.user = &profile;
        decoded.tracker = nullptr;
        decoded.limiter = nullptr;
    }
    std::string socket_key;
    SocketPtr socket;
    app::DatagramSessionEnvironment environment;
    UdpDatagramContext context;
    InboundDatagramResult decoded;
    UserProfile profile;
    std::shared_ptr<InboundDatagramResponse> response;
    UdpResourceBudget::PayloadReservation reservation;
};

net::awaitable<void> UdpIngress::ProcessAuthenticated(
    std::shared_ptr<AuthenticatedPacket> packet) {
    co_await net::this_coro::reset_cancellation_state(net::disable_cancellation());
    auto& context = packet->context;
    auto& decoded = packet->decoded;
    auto coordinator = packet->environment.coordinator;
    UdpHandoffIdentity identity{
        packet->socket_key, std::string(impl_->tag),
        packet->environment.prepared->settings.get(),
        ClientSessionKey{decoded.session_owner, decoded.session_id, {},
                         packet->environment.prepared->settings.get()}};
    auto configuration = packet->environment.prepared->settings;
    auto record = co_await coordinator->PostCall(
        [coordinator, identity = std::move(identity), configuration,
         policy = decoded.association_policy] {
            return net::use_service<UdpHandoffDirectory>(coordinator->Services())
                .Claim(identity, configuration, *policy);
        });
    if (!record) co_return;
    auto release_claim = MakeScopeExit([record] {
        record->association->claimed.store(false, std::memory_order_release);
    });
    if (impl_->state != Impl::State::Running ||
        !OwnsSocket(packet->socket_key, context.sock)) co_return;
    auto session = record->session.lock();
    auto domain = record->domain.lock();
    auto release_foreign = MakeScopeExit([&session, &domain, worker_id = context.worker_id]() noexcept {
        if (domain && !domain->CanDestroyDirectlyOn(worker_id)) {
            auto* target = domain.get();
            try {
                target->Execute([session = std::move(session),
                                 domain = std::move(domain)]() mutable {
                    session.reset();
                    domain.reset();
                });
            } catch (...) {
                FailRuntime("udp-handoff", "failed to return foreign session ownership");
            }
        }
    });
    if (!session) {
        if (!record->association->Check(*decoded.packet_id, context.worker_id,
                context.client_endpoint, InboundDatagramCheck::Commit))
            co_return;
        packet->reservation = {};
        ProcessDecoded(context, std::move(decoded), record, std::move(packet->response));
        co_return;
    }
    if (!domain) co_return;
    if (record->owner == context.worker_id) {
        if (session->Closed() ||
            !record->association->Check(*decoded.packet_id, context.worker_id,
                context.client_endpoint, InboundDatagramCheck::Commit))
            co_return;
        session->UpdateReplyEndpoint(context.client_endpoint);
        if (auto* hook = session->impl_->association_hook) {
            auto outer = impl_->client_sessions.find(hook->socket_key);
            if (outer != impl_->client_sessions.end()) {
                auto row = outer->second.find(*hook->client_key);
                if (row != outer->second.end()) row->second.last_active = std::chrono::steady_clock::now();
            }
        }
        packet->reservation = {};
        (void)session->Push(decoded.target, std::move(decoded.payload));
        co_return;
    }
    const uint32_t previous = domain->OwnerId();
    auto socket = FindSocket(packet->socket_key);
    ReplyRoute next{
        .socket_key = memory::ThreadLocalString(packet->socket_key),
        .socket = std::move(socket),
        .response = {},
        .sink = &context.reply_sink,
        .worker_id = context.worker_id,
        .fence = std::make_shared<UdpReplyFence>(context.io_context)};
    // The source sees authenticated metadata only. Protocol inspection precedes
    // freezing; its continuity state commits once under the exclusive lease.
    auto prepare_metadata = [session, destination = this, next = std::move(next),
                             packet_id = *decoded.packet_id, worker = context.worker_id,
                             endpoint = context.client_endpoint]() mutable -> net::awaitable<bool> {
        auto& state = *session->impl_;
        if (session->Closed() || state.transferring || !state.association_hook) co_return false;
        if (!state.handoff_record->association->Check(
                packet_id, worker, endpoint, InboundDatagramCheck::Inspect)) co_return false;
        next.response = state.reply.response;
        state.destination = destination;
        state.next_reply = std::move(next);
        co_return true;
    };
    if (!co_await net::co_spawn(domain->Executor(), prepare_metadata(), net::use_awaitable))
        co_return;
    std::shared_ptr<ExecutionDomain::Handoff> handoff;
    std::exception_ptr failure;
    bool accepted = false;
    try {
        handoff = co_await domain->PreparePassiveHandoff({
            context.worker_id, &context.io_context, context.io_context.get_executor()});
        co_await handoff->Validate([&] {
            if (impl_->state == Impl::State::Running &&
                OwnsSocket(packet->socket_key, context.sock) &&
                session->impl_->transferring && !session->impl_->close_pending)
                accepted = record->association->Check(*decoded.packet_id, context.worker_id,
                    context.client_endpoint, InboundDatagramCheck::Commit);
        });
        if (accepted) {
            co_await handoff->Commit();
            handoff.reset();
            const auto committed_owner = domain->OwnerId();
            if (committed_owner != context.worker_id)
                FailRuntime("udp-handoff", "commit did not move to the receiving Worker");
            record->owner = committed_owner;
            session->UpdateReplyEndpoint(context.client_endpoint);
            if (auto* hook = session->impl_->association_hook) {
                auto outer = impl_->client_sessions.find(hook->socket_key);
                auto row = outer->second.find(*hook->client_key);
                row->second.last_active = std::chrono::steady_clock::now();
            }
            packet->reservation = {};
            (void)session->Push(decoded.target, std::move(decoded.payload));
            LOG_NET_DEBUG("UDP passive handoff worker={} previous_worker={} session={}",
                          committed_owner, previous, *decoded.session_id);
        }
    } catch (...) { failure = std::current_exception(); }
    if (handoff) co_await handoff->Cancel();
    if (failure && !handoff) {
        // Prepare may reject before invoking our resource. Remove the staged
        // target metadata before its listener lifetime pin is released.
        auto clear_staging = [session]() -> net::awaitable<void> {
            if (!session->impl_->transferring) {
                session->impl_->destination = nullptr;
                session->impl_->next_reply.reset();
            }
            co_return;
        };
        co_await net::co_spawn(domain->Executor(), clear_staging(), net::use_awaitable);
    }
    if (failure) std::rethrow_exception(failure);
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
            !datagram.environment->prepared->settings ||
            impl_->controls >= kMaxQueuedUdpDatagrams) return;
        auto reservation = impl_->budget.ReservePayload(decoded->payload);
        if (!reservation) return;
        auto response = impl_->proxy->CreateDatagramResponse(*decoded);
        if (!response || !*response) return;
        auto packet = std::make_shared<AuthenticatedPacket>(
            datagram, std::move(*decoded), std::move(*response), std::move(reservation),
            FindSocket(socket_key));
        ++impl_->controls;
        try {
            net::co_spawn(datagram.io_context, ProcessAuthenticated(std::move(packet)),
                [this](std::exception_ptr error) {
                    ReleaseControl();
                    if (error) {
                        try { std::rethrow_exception(error); }
                        catch (const std::exception& e) { LOG_NET_DEBUG("UDP claim rejected > {}", e.what()); }
                        catch (...) {}
                    }
                });
        } catch (...) { ReleaseControl(); throw; }
        return;
    }
    ProcessDecoded(datagram, std::move(*decoded));
}

void UdpIngress::ProcessDecoded(const UdpDatagramContext& datagram,
    InboundDatagramResult result, std::shared_ptr<UdpHandoffRecord> record,
    std::shared_ptr<InboundDatagramResponse> prepared_response) {
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
        auto response = prepared_response
            ? tl::expected<std::shared_ptr<InboundDatagramResponse>, ErrorCode>(std::move(prepared_response))
            : impl_->proxy->CreateDatagramResponse(*decoded);
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
            .worker_id = worker_id,
            .fence = std::make_shared<UdpReplyFence>(datagram.io_context)};

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
        if (datagram.environment) {
            const auto& env = *datagram.environment;
            session_impl.registry = env.registry;
            session_impl.capabilities = app::PhysicalSessionCapabilities::Create(
                env.configuration, env.limiter, env.request_load, *env.dns_worker,
                env.prepared, env.receiver);
            session_impl.domain = ExecutionDomain::Create(
                datagram.io_context, worker_id, datagram.io_context.get_executor(),
                session_impl.capabilities, env.coordinator);
            session_impl.capabilities->BindDomain(session_impl.domain);
            if (record) {
                record->session = client_session;
                record->domain = session_impl.domain;
                record->owner = worker_id;
                auto socket = impl_->udp_sockets.find(socket_key);
                if (socket == impl_->udp_sockets.end() ||
                    socket->second.socket.get() != datagram.sock) return;
                socket->second.associations.insert_or_assign(
                    InboundDatagramAssociationKey{decoded->session_owner, *decoded->session_id,
                        client_session_key.configuration},
                    record->association.get());
            }
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
        request.tracker = datagram.environment ? nullptr : decoded->tracker;
        request.limiter = datagram.environment ? nullptr : decoded->limiter;
        ::proxy::BindAuthenticatedInbound(
            ctx, request.profile,
            ::proxy::InboundRequestTarget{
                Network::UDP,
                decoded->target,
                std::move(decoded->forwarded)});
        request.dispatcher = datagram.dispatcher;
        request.io_context = &datagram.io_context;
        request.stats = datagram.environment ? nullptr : &datagram.stats;
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
                session_impl.domain ? session_impl.domain->Executor() :
                    net::any_io_executor(datagram.io_context.get_executor()),
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
    buf::MultiBuffer payload,
    std::shared_ptr<UdpReplyFence> fence) {
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
    reply.fence = UdpReplyFence::Lease(std::move(fence));
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
