#include "app/udp_ingress.hpp"
#include "app/relay.hpp"
#include "app/udp_session_relay.hpp"
#include "app/inbound_handler.hpp"
#include "app/request_load.hpp"
#include "common/awaitable_task_group.hpp"
#include "proxy/inbound_admission.hpp"

#include "common/multi_buffer.hpp"
#include "common/ip_address.hpp"
#include "common/session.hpp"
#include "common/allocator.hpp"
#include "common/hash.hpp"
#include "routing/dispatcher.hpp"
#include "infra/config_types.hpp"
#include "infra/log.hpp"
#include "transport/async_stream.hpp"

#include <openssl/sha.h>

#include <asio/as_tuple.hpp>
#include <asio/bind_cancellation_slot.hpp>
#include <asio/co_spawn.hpp>
#include <asio/experimental/channel.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/this_coro.hpp>

#include <algorithm>
#include <exception>
#include <limits>
#include <stdexcept>
#include <utility>

namespace app {

namespace {
// Rows inspected per wake; further due rows wait for the next event-loop turn.
constexpr std::size_t kMaxChecks = 64;
}

UdpAssociationHook::TimePoint UdpAssociationExpiry(
    UdpAssociationHook::TimePoint last_active, std::chrono::seconds idle_timeout) noexcept {
    using TimePoint = UdpAssociationHook::TimePoint;
    if (idle_timeout <= std::chrono::seconds::zero()) return TimePoint::max();
    // Saturate instead of overflowing the clock: such a row never expires.
    if (idle_timeout >= std::chrono::duration_cast<std::chrono::seconds>(
            TimePoint::max() - last_active)) {
        return TimePoint::max();
    }
    return last_active + idle_timeout;
}

UdpAssociationReclaimer::UdpAssociationReclaimer(
    transport::TimeoutScheduler& scheduler,
    void* failure_context,
    FailureCallback on_failure) noexcept
    : scheduler_(scheduler)
    , failure_context_(failure_context)
    , on_failure_(on_failure) {}

UdpAssociationReclaimer::~UdpAssociationReclaimer() noexcept { Stop(); }

void UdpAssociationReclaimer::ReserveRow() {
    if (heap_.size() < heap_.capacity()) return;
    heap_.reserve(std::max<std::size_t>(4, heap_.capacity() * 2));
}

void UdpAssociationReclaimer::Register(
    UdpAssociationHook& hook, UdpIngress& owner, UdpSocketState& socket,
    const ClientSessionKey& client_key, std::chrono::seconds idle_timeout,
    TimePoint deadline) noexcept {
    if (stopped_) {
        common::FailRuntime("udp-maintenance", "association registered after reclaimer stop");
    }
    if (hook.owner) {
        common::FailRuntime("udp-maintenance", "association hook registered twice");
    }
    if (heap_.size() == heap_.capacity()) {
        common::FailRuntime("udp-maintenance", "association registered without reserved capacity");
    }
    hook.owner = &owner;
    hook.socket = &socket;
    hook.client_key = &client_key;
    hook.idle_timeout = idle_timeout;
    hook.deadline = deadline;
    heap_.push_back(&hook);
    SiftUp(heap_.size() - 1);
    Schedule();
}

void UdpAssociationReclaimer::Rearm(UdpAssociationHook& hook, TimePoint deadline) noexcept {
    if (!hook.owner) return;
    hook.deadline = deadline;
    Repair(hook.heap_index);
    Schedule();
}

void UdpAssociationReclaimer::Unregister(UdpAssociationHook& hook) noexcept {
    if (!hook.owner) return;
    const auto index = hook.heap_index;
    auto* last = heap_.back();
    heap_.pop_back();
    if (index != heap_.size()) {
        Place(index, last);
        Repair(index);
    }
    hook = {};
    if (heap_.empty()) {
        scheduler_.Cancel(*this);
        // Idle Workers release the index storage.
        decltype(heap_){}.swap(heap_);
    }
}

void UdpAssociationReclaimer::Stop() noexcept {
    if (stopped_) return;
    stopped_ = true;
    scheduler_.Cancel(*this);
}

void UdpAssociationReclaimer::OnTimeout() noexcept {
    if (stopped_) return;
    const auto now = std::chrono::steady_clock::now();
    running_batch_ = true;
    // Re-read the head each time: reclaiming may synchronously unlink other rows.
    // The owner either unlinks the row or re-arms it no earlier than `now`.
    for (std::size_t checks = 0;
         checks < kMaxChecks && !heap_.empty() && heap_.front()->deadline < now; ++checks) {
        auto& row = *heap_.front();
        row.owner->ReclaimAssociation(row, now);
    }
    running_batch_ = false;
    Schedule();
}

void UdpAssociationReclaimer::Schedule() noexcept {
    if (stopped_ || failed_ || running_batch_) return;
    if (heap_.empty() || heap_.front()->deadline == TimePoint::max()) {
        scheduler_.Cancel(*this);
        return;
    }
    const auto deadline = heap_.front()->deadline;
    // A pending wake at or before the head is kept: a wake that finds nothing
    // due only re-arms, so the event is moved earlier, never pushed back.
    if (Valid() && armed_deadline_ <= deadline) return;
    const auto now = std::chrono::steady_clock::now();
    const auto delay = deadline <= now
        ? std::chrono::milliseconds::zero()
        : std::chrono::ceil<std::chrono::milliseconds>(deadline - now);
    try {
        if (!scheduler_.ScheduleAfter(delay, *this))
            common::FailRuntime("udp-maintenance", "association schedule refused after release");
        armed_deadline_ = deadline;
    } catch (...) {
        failed_ = true;
        if (on_failure_) on_failure_(failure_context_, std::current_exception());
    }
}

void UdpAssociationReclaimer::Place(std::size_t index, UdpAssociationHook* hook) noexcept {
    heap_[index] = hook;
    hook->heap_index = index;
}

void UdpAssociationReclaimer::SiftUp(std::size_t index) noexcept {
    auto* hook = heap_[index];
    while (index != 0) {
        const auto parent = (index - 1) / 2;
        if (!(hook->deadline < heap_[parent]->deadline)) break;
        Place(index, heap_[parent]);
        index = parent;
    }
    Place(index, hook);
}

void UdpAssociationReclaimer::SiftDown(std::size_t index) noexcept {
    auto* hook = heap_[index];
    const auto size = heap_.size();
    for (;;) {
        auto child = index * 2 + 1;
        if (child >= size) break;
        if (child + 1 < size && heap_[child + 1]->deadline < heap_[child]->deadline) ++child;
        if (!(heap_[child]->deadline < hook->deadline)) break;
        Place(index, heap_[child]);
        index = child;
    }
    Place(index, hook);
}

void UdpAssociationReclaimer::Repair(std::size_t index) noexcept {
    if (index != 0 && heap_[index]->deadline < heap_[(index - 1) / 2]->deadline) {
        SiftUp(index);
    } else {
        SiftDown(index);
    }
}

std::span<const net::const_buffer>
UdpIngress::PendingUdpReply::SendBuffers() const noexcept {
    return send_buffer.size() == 0
        ? std::span<const net::const_buffer>{}
        : std::span<const net::const_buffer>(&send_buffer, 1);
}

namespace {

using proxy::NativeAssociationAdmission;

constexpr size_t kMaxQueuedUdpDatagrams = 256;
constexpr size_t kMaxQueuedUdpBytes = 512 * 1024;
// Sessions whose owner the directory is deciding, and datagrams each holds
// meanwhile: one coordinator round trip.
constexpr size_t kMaxPendingSessionClaims = 4096;
constexpr size_t kMaxPendingClaimDatagrams = 32;
// Sessions of other Workers this ingress forwards to.
constexpr size_t kMaxRemoteRoutes = 64 * 1024;

// Names a replay-protected session process-wide: the listener (its prepared
// configuration and bound endpoint, the same on every Worker) and the
// authenticated session key.
[[nodiscard]] SessionOwnerKey NativeSessionOwnerKey(
    const UdpSocketState& socket, const ClientSessionKey& client) noexcept {
    constexpr std::string_view kNamespace = "cnode/native-udp-session";
    const auto configuration = static_cast<uint64_t>(
        reinterpret_cast<uintptr_t>(client.configuration));
    const auto bound = PackedUdpEndpoint::From(socket.bound_endpoint);
    const uint64_t session_id = client.session_id.value_or(0);
    SHA256_CTX context;
    SHA256_Init(&context);
    SHA256_Update(&context, kNamespace.data(), kNamespace.size());
    SHA256_Update(&context, &configuration, sizeof(configuration));
    SHA256_Update(&context, bound.address.data(), bound.address.size());
    SHA256_Update(&context, &bound.port, sizeof(bound.port));
    SHA256_Update(&context, &bound.v6, sizeof(bound.v6));
    SHA256_Update(&context, &client.owner.size, sizeof(client.owner.size));
    SHA256_Update(&context, client.owner.bytes.data(), client.owner.size);
    SHA256_Update(&context, &session_id, sizeof(session_id));
    SessionOwnerKey key;
    SHA256_Final(key.data(), &context);
    return key;
}


[[nodiscard]] bool WouldOverflowUdpQueue(
    size_t queued_datagrams,
    size_t queued_bytes,
    size_t payload_size) noexcept {
    return queued_datagrams >= kMaxQueuedUdpDatagrams ||
        payload_size > kMaxQueuedUdpBytes ||
        queued_bytes > kMaxQueuedUdpBytes - payload_size;
}

template <typename SessionRow>
[[nodiscard]] bool ShouldReclaim(
    const SessionRow& session,
    std::chrono::steady_clock::time_point now,
    std::chrono::seconds idle_timeout) noexcept {
    return !session.link || session.link->Closed() ||
        (idle_timeout.count() > 0 && now - session.reclaim_hook.last_active > idle_timeout);
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

// Upper bound of what a protocol adds around a reply's payload (SS2022:
// headers, padding and the longest address).
constexpr size_t kReplyEncodingOverhead = 512;

// Waits on a session's channel until signalled or `cancellation` fires.
struct ReplyRoomWait final : common::CancellationSubscription {
    explicit ReplyRoomWait(common::SignalChannel& signal) noexcept : signal(signal) {}
    common::SignalChannel& signal;
    bool cancelled = false;

private:
    void OnCancellation(common::Cancellation) noexcept override {
        cancelled = true;
        (void)signal.try_send(IoErrorCode{});
    }
};

}  // namespace

bool UdpIngress::HasReplyRoom(const SocketState& socket, size_t bytes) const noexcept {
    return !WouldOverflowUdpQueue(socket.pending.size(), socket.queued_bytes, bytes);
}

net::awaitable<bool> UdpIngress::AwaitReplyRoom(SocketState& socket, ClientSession& session) {
    socket.reply_waiters.push_back(&session);
    struct Leave {
        SocketState& socket;
        ClientSession* session;
        ~Leave() { std::erase(socket.reply_waiters, session); }
    } leave{socket, &session};
    ReplyRoomWait watch(session.reply_room_signal_);
    watch.Resubscribe(session.cancellation_);
    if (!watch.cancelled && !session.Closed()) {
        auto [error] = co_await session.reply_room_signal_.async_receive(
            net::as_tuple(net::use_awaitable));
        if (error) co_return false;
    }
    co_return !watch.cancelled && !session.Closed() && OwnsSocket(socket);
}

bool UdpIngress::ReplyRoute::Send(proxy::UDPPacketView packet, const udp::endpoint& endpoint) {
    auto payload = response->Encode(packet);
    if (payload.empty()) return false;
    return owner->SendReply(socket, endpoint, std::move(payload), worker_id);
}

UdpIngress::ClientSession::ClientSession(
    net::io_context& io_context,
    ReplyRoute reply,
    udp::endpoint reply_endpoint,
    proxy::InboundDatagramOwner session_owner,
    UdpResourceBudget& budget,
    UdpResourceBudget::AssociationLease association,
    std::shared_ptr<UdpHandoffRecord> record)
    : association_(std::move(association))
    , budget_(&budget)
    , reader_signal_(io_context, 1)
    , reply_room_signal_(io_context, 1)
    , reply_(std::move(reply))
    , reply_endpoint_(std::move(reply_endpoint))
    , session_owner_(std::move(session_owner))
    , handoff_record_(std::move(record)) {}

UdpIngress::ClientSession::~ClientSession() noexcept {
    Close();
    // A replay tombstone needs the association, not the expired weak owner of
    // this make_shared allocation. The implicit weak reference keeps the
    // control block alive until this destructor returns.
    if (handoff_record_ && handoff_record_->session.expired())
        handoff_record_->session.reset();
}

common::CancellationSource& UdpIngress::ClientSession::Cancellation() noexcept {
    return cancellation_;
}

bool UdpIngress::ClientSession::Closed() const noexcept {
    return closed_;
}

bool UdpIngress::ClientSession::Owns(
    const proxy::InboundDatagramOwner& owner) const noexcept {
    return session_owner_.Same(owner);
}

void UdpIngress::ClientSession::UpdateReplyEndpoint(
    udp::endpoint endpoint) noexcept {
    reply_endpoint_ = std::move(endpoint);
}

bool UdpIngress::ClientSession::Push(
    const common::TargetAddress& target,
    common::MultiBuffer payload) {
    const size_t payload_size = payload.byte_size();
    if (Closed()) {
        payload.clear();
        return false;
    }
    // A burst beyond the queue loses datagrams, as UDP may; the session and
    // its outbound stay.
    if (WouldOverflowUdpQueue(
            input_queue_.size(), queued_bytes_, payload_size)) {
        payload.clear();
        return false;
    }

    if (!common::SetUdpTarget(payload, target)) return false;
    auto reservation = budget_->ReservePayload(payload);
    if (!reservation) return false;

    QueuedInput input{std::move(payload), payload_size, std::move(reservation)};
    input_queue_.push_back(std::move(input));
    queued_bytes_ += payload_size;
    WakeReader();
    return true;
}

void UdpIngress::ClientSession::Close() noexcept {
    CloseWithError(common::ErrorCode::OK);
}

bool UdpIngress::ClientSession::TryReadMultiBuffer(common::MultiBuffer& out) noexcept {
    if (input_queue_.empty()) return false;
    auto input = std::move(input_queue_.front());
    queued_bytes_ -= std::min(queued_bytes_, input.bytes);
    input_queue_.pop_front();
    out = std::move(input.payload);
    return true;
}

net::awaitable<common::MultiBuffer>
UdpIngress::ClientSession::ReadMultiBuffer() {
    while (true) {
        if (common::MultiBuffer payload; TryReadMultiBuffer(payload)) co_return payload;

        if (closed_) {
            if (terminal_error_ == common::ErrorCode::RESOURCE_EXHAUSTED) {
                throw IoSystemError(
                    io_error::no_buffer_space,
                    "UDP client input queue full");
            }
            if (terminal_error_ != common::ErrorCode::OK) {
                throw transport::LinkError(terminal_error_);
            }
            co_return common::MultiBuffer{};
        }

        auto [ec] = co_await reader_signal_.async_receive(
            net::as_tuple(net::use_awaitable));
        if (ec) {
            throw IoSystemError(
                io_error::operation_aborted,
                "UDP client input cancelled");
        }
    }
}

net::awaitable<void>
UdpIngress::ClientSession::WriteMultiBuffer(common::MultiBuffer mb) {
    if (Closed() || !reply_.Valid()) {
        mb.clear();
        throw IoSystemError(
            io_error::operation_aborted,
            "UDP client reply path closed");
    }

    const auto datagram = common::InspectUdpDatagram(mb);
    if (datagram.status == common::UdpDatagramStatus::Empty) {
        mb.clear();
        co_return;
    }
    if (!datagram.Valid()) {
        mb.clear();
        throw IoSystemError(
            io_error::invalid_argument,
            "UDP client reply contains missing or mixed endpoints");
    }

    // The socket's reply queue is shared by its sessions: a burst waits for
    // room, holding back this session's outbound, rather than being lost.
    while (!reply_.owner->HasReplyRoom(
               *reply_.socket, datagram.payload_size + kReplyEncodingOverhead)) {
        if (!co_await reply_.owner->AwaitReplyRoom(*reply_.socket, *this)) {
            mb.clear();
            throw IoSystemError(io_error::operation_aborted, "UDP client reply path closed");
        }
    }
    // An encoding or queueing failure loses this datagram only.
    (void)reply_.Send(proxy::UDPPacketView{*datagram.target, mb.FrontSpan()}, reply_endpoint_);
    mb.clear();
    co_return;
}

std::optional<UdpIngress::PendingUdpReply> UdpIngress::BeginReplySend(
    SocketState& queue) {
    if (queue.active_id != 0 || queue.pending.empty()) return std::nullopt;
    if (last_reply_id_ == std::numeric_limits<uint64_t>::max())
        throw IoSystemError(io_error::no_buffer_space, "UDP reply send generation exhausted");

    auto& front = queue.pending.front();
    const auto front_bytes = front.payload.FrontSpan();
    std::optional<PendingUdpReply> packet{std::in_place};
    packet->send_buffer = net::buffer(front_bytes.data(), front_bytes.size());
    packet->id = ++last_reply_id_;
    packet->endpoint = std::move(front.endpoint);
    packet->payload = std::move(front.payload);
    packet->reservation = std::move(front.reservation);
    const size_t payload_size = front.payload_size;
    queue.queued_bytes -= payload_size;
    queue.pending.pop_front();
    for (auto* waiter : queue.reply_waiters) (void)waiter->reply_room_signal_.try_send(IoErrorCode{});
    queue.active_id = packet->id;
    queue.active_payload_size = payload_size;
    return packet;
}

void UdpIngress::Link(UdpClientSession& row, SocketState& socket,
                      const ClientSessionKey& client_key, std::chrono::seconds idle_timeout) noexcept {
    reclaimer_.Register(row.reclaim_hook, *this, socket, client_key, idle_timeout,
                        UdpAssociationExpiry(row.reclaim_hook.last_active, idle_timeout));
    row.link->association_hook_ = &row.reclaim_hook;
}

void UdpIngress::SetLocalAssociation(const UdpAssociationHook& hook,
                                     proxy::InboundDatagramAssociation* association) noexcept {
    if (!hook.client_key || !hook.client_key->session_id) return;
    if (!hook.socket) return;
    const auto& key = *hook.client_key;
    auto entry = hook.socket->associations.find(
        proxy::InboundDatagramAssociationKey{key.owner, *key.session_id, key.configuration});
    if (entry != hook.socket->associations.end()) entry->second = association;
}

void UdpIngress::Unlink(UdpClientSession& row) noexcept {
    const auto& hook = row.reclaim_hook;
    if (hook.client_key && hook.client_key->session_id) {
        if (hook.socket) {
            const auto& key = *hook.client_key;
            hook.socket->associations.erase(
                proxy::InboundDatagramAssociationKey{key.owner, *key.session_id, key.configuration});
        }
    }
    reclaimer_.Unregister(row.reclaim_hook);
    if (row.link) row.link->association_hook_ = nullptr;
}

void UdpIngress::ClientSession::CloseWithError(common::ErrorCode error) noexcept {
    if (closed_) {
        return;
    }
    closed_ = true;
    terminal_error_ = error;
    if (relay_token_ && reply_.owner) reply_.owner->ReleaseOwnedSession(*this);
    // Closure is the row's reclaim event. Re-arm before cancellation callbacks
    // can re-enter the ingress and unlink the row.
    if (auto* hook = association_hook_) {
        hook->owner->SetLocalAssociation(*hook, nullptr);
        hook->owner->reclaimer_.Rearm(*hook, UdpAssociationHook::TimePoint::min());
    }
    cancellation_.Stop(error);
    input_queue_.clear();
    queued_bytes_ = 0;
    WakeReader();
}

UdpIngress::UdpIngress(
    std::string_view tag,
    std::unique_ptr<::proxy::Inbound> proxy,
    UdpAssociationReclaimer& reclaimer,
    UdpResourceBudget& budget,
    net::io_context& io_context)
    : tag_(tag)
    , proxy_(std::move(proxy))
    , reclaimer_(reclaimer)
    , budget_(budget)
    , io_context_(io_context)
    , completion_signal_(io_context, 1)
    , relay_(common::FindWorkerMesh<UdpSessionRelay>(io_context)) {}

UdpIngress::~UdpIngress() noexcept {
    if (Busy()) {
        common::FailRuntime("udp-ingress", "destroyed with native dispatch jobs outstanding");
    }
    RequestStop();
}

UdpIngress::ResourceStats UdpIngress::GetResourceStats() const noexcept {
    ResourceStats stats{};
    for (const auto& [identity, socket] : sockets_) {
        (void)identity;
        for (const auto& [client_key, session] : socket->sessions) {
            (void)client_key;
            ++stats.associations;
            if (!session.link || session.link->Closed()) {
                ++stats.closed_associations;
            }
            if (session.link) {
                stats.input_datagrams += session.link->input_queue_.size();
                stats.input_bytes += session.link->queued_bytes_;
            }
        }
        const auto& queue = *socket;
        stats.reply_datagrams += queue.pending.size();
        stats.reply_bytes += queue.queued_bytes;
        if (queue.active_id != 0) {
            ++stats.active_reply_senders;
            ++stats.reply_datagrams;
            stats.reply_bytes += queue.active_payload_size;
        }
    }
    stats.native_dispatches = outstanding_jobs_;
    return stats;
}

bool UdpIngress::ReplaceHandler(
    std::unique_ptr<::proxy::Inbound> proxy) noexcept {
    if (!proxy) {
        return false;
    }
    proxy_ = std::move(proxy);
    return true;
}

void UdpIngress::RequestStop() noexcept {
    if (state_ != State::Running) return;
    state_ = State::Stopping;
    while (!sockets_.empty()) {
        CloseSocket(*sockets_.begin()->second);
    }

    CloseMatchingJobs([](const ClientSession&) noexcept { return true; });
    // Claims still in flight resolve to nothing once stopping.
    if (relay_) {
        for (const auto& [token, owned] : owned_tokens_) {
            (void)owned;
            relay_->ReleaseToken(token);
        }
    }
    owned_tokens_.clear();
    NotifyCompletion();
}

net::awaitable<void> UdpIngress::AsyncJoin() {
    const bool previous_throw_setting = co_await net::this_coro::throw_if_cancelled();
    co_await net::this_coro::throw_if_cancelled(false);
    std::exception_ptr failure;
    const bool observer_conflict = join_observers_ != 0;
    if (!observer_conflict) {
        ++join_observers_;
        struct ReleaseObserver {
            size_t& observers;
            ~ReleaseObserver() { --observers; }
        } release{join_observers_};
        try {
            while (Busy()) {
                auto [ec] = co_await completion_signal_.async_receive(
                    net::as_tuple(asio::bind_cancellation_slot(
                        asio::cancellation_slot{}, net::use_awaitable)));
                if (ec && Busy())
                    throw IoSystemError(ec, "UDP native dispatch join failed");
            }
            if (state_ == State::Stopping)
                state_ = State::Drained;
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
    if (!session.job_registered_) return;
    if (session.job_linked_) {
        if (session.job_previous_)
            session.job_previous_->job_next_ = session.job_next_;
        else if (jobs_ == &session)
            jobs_ = session.job_next_;
        if (session.job_next_)
            session.job_next_->job_previous_ = session.job_previous_;
    }
    session.job_previous_ = nullptr;
    session.job_next_ = nullptr;
    session.job_registered_ = false;
    session.job_linked_ = false;
    if (outstanding_jobs_ == 0) {
        common::FailRuntime("udp-ingress", "native dispatch completion underflow");
    }
    --outstanding_jobs_;
    NotifyCompletion();
}

void UdpIngress::RetireNativeJob(ClientSession& session) noexcept {
    session.job_pin_.reset();
    session.request_.reset();
    DetachNativeJob(session);
}

void UdpIngress::RegisterNativeJob(const ClientSessionPtr& session) {
    session->job_registered_ = true;
    session->job_pin_ = session;
    session->job_previous_ = nullptr;
    session->job_next_ = jobs_;
    session->job_linked_ = true;
    if (jobs_) jobs_->job_previous_ = session.get();
    jobs_ = session.get();
    ++outstanding_jobs_;
}

// One run per association. Admission happens before the first Dispatch;
// packets arriving meanwhile wait in the bounded association queue, and a
// rejection closes the association, dropping them. The frame owns the
// connection reservations and the online-device guard until it ends.
net::awaitable<void> UdpIngress::RunNativeDispatch(ClientSessionPtr client_session) {
    auto& request = *client_session->request_;
    app::RequestLoadState::PhysicalConnectionScope physical(*request.request_load);
    ConnectionStatsScope connection_stats(request.admission->stats);
    std::optional<NativeAssociationAdmission> admission;
    try {
        auto authentication = co_await proxy::BeginInboundAuthentication(*request.admission, request.context);
        if (!authentication) {
            request.admission->stats.OnError();
            client_session->Close();
            co_return;
        }
        auto bound = std::move(*authentication).Bind(request.profile, std::nullopt);
        request.profile = {};
        admission = co_await NativeAssociationAdmission::Admit(
            *request.admission, request.context, std::move(bound));
        if (!admission || client_session->Closed()) {
            client_session->Close();
            co_return;
        }
        RelayResult result = co_await proxy::DispatchAuthenticatedInbound(*request.dispatcher,
            *request.io_context, request.policy,
            routing::DispatchRequest{transport::Link{client_session.get(), client_session.get()}},
            request.context, request.admission->stats, request.timeouts);
        if (result.error != common::ErrorCode::OK) {
            LOG_CONN_DEBUG(request.context,
                "UDP dispatcher ended > {} up={}B down={}B",
                common::ErrorCodeToString(result.error), result.bytes_up,
                result.bytes_down);
        }
    } catch (const IoSystemError& error) {
        if (error.code() != net::error::operation_aborted && error.code() != net::error::eof) {
            LOG_CONN_ERROR(request.context, "UDP dispatcher failed worker={} > {}",
                           request.context.worker_id, error.what());
        }
    } catch (const std::exception& e) {
        LOG_CONN_ERROR(request.context, "UDP dispatcher coroutine failed worker={} > {}",
                  request.context.worker_id, e.what());
    } catch (...) {
        LOG_CONN_ERROR(request.context, "UDP dispatcher coroutine failed worker={} > unknown error",
                  request.context.worker_id);
    }
    client_session->Close();
    co_return;
}

void UdpIngress::ProcessDatagram(const UdpDatagramContext& datagram) {
    if (state_ != State::Running || !proxy_ ||
        !datagram.socket || !OwnsSocket(*datagram.socket) || datagram.payload.empty()) {
        return;
    }
    if (!datagram.receiver) {
        LOG_NET_DEBUG(
            "UDP datagram rejected worker={} tag={} > missing prepared receiver",
            datagram.worker_id,
            tag_);
        return;
    }

    auto& socket = *datagram.socket;
    const auto now = std::chrono::steady_clock::now();

    auto decoded = proxy_->Process(proxy::InboundDatagramRequest{
        .tag = tag_,
        .payload = datagram.payload,
        .associations = &socket.associations,
        .configuration = datagram.environment.prepared
            ? datagram.environment.prepared->settings.get() : nullptr,
        .worker_id = datagram.worker_id,
        .client_endpoint = datagram.client_endpoint,
    });
    if (!decoded) {
        if (decoded.error() == common::ErrorCode::PROTOCOL_AUTH_FAILED &&
            (::infra::Log::ShouldLog(::infra::LogLevel::WARN) ||
             ::infra::Log::IsInitialized())) {
            // Datagram sources are socket peers, never PROXY protocol clients,
            // so a credential failure is logged without feeding the ban table.
            const auto normalized_client_addr =
                common::NormalizeAddress(datagram.client_endpoint.address());
            common::Context rejected;
            rejected.worker_id = datagram.worker_id;
            rejected.inbound.tag = tag_;
            rejected.inbound.source_addr = normalized_client_addr;
            rejected.inbound.source_ip = common::AddressText(normalized_client_addr).View();
            rejected.inbound.source_port = datagram.client_endpoint.port();
            ::proxy::LogInboundAuthFailure(
                rejected, "datagram authentication or validation failed");
        }
        (void)proxy::RejectInbound(datagram.environment.admission->stats, nullptr, decoded.error());
        return;
    }
    if (decoded->association_policy && decoded->session_id && decoded->packet_id) {
        const auto& prepared = datagram.environment.prepared;
        if (!prepared || !prepared->settings) return;
        if (decoded->committed_association) {
            const ClientSessionKey key{decoded->session_owner, decoded->session_id, {},
                                       prepared->settings.get()};
            if (auto row = socket.sessions.find(key); row != socket.sessions.end()) {
                if (row->second.link) {
                    auto session = row->second.link;
                    if (session->handoff_record_ && !session->Closed() &&
                        session->handoff_record_->association.get() == decoded->committed_association) {
                        row->second.reclaim_hook.last_active = now;
                        session->UpdateReplyEndpoint(datagram.client_endpoint);
                        (void)session->Push(decoded->target, std::move(decoded->payload));
                    }
                }
            }
            return;
        }
        if (!decoded->user) return;
        const UdpHandoffIdentity identity{
            &socket,
            ClientSessionKey{decoded->session_owner, decoded->session_id, {},
                             prepared->settings.get()}};
        if (relay_ && RouteSessionDatagram(datagram, identity, *decoded)) return;
        DeliverSessionDatagram(datagram, identity, std::move(*decoded), now);
        return;
    }
    ProcessDecoded(datagram, std::move(*decoded), now);
}

void UdpIngress::DeliverSessionDatagram(const UdpDatagramContext& datagram,
    const UdpHandoffIdentity& identity, proxy::InboundDatagramResult decoded,
    std::chrono::steady_clock::time_point now) {
    auto record = handoff_directory_.Claim(
        identity, datagram.environment.prepared->settings, *decoded.association_policy);
    if (!record) return;
    record->socket_pin = datagram.socket->shared_from_this();
    auto release_claim = MakeScopeExit([record]() noexcept {
        record->association->claimed = false;
    });
    if (auto session = record->session.lock()) {
        if (session->Closed() ||
            !record->association->Check(*decoded.packet_id, datagram.worker_id,
                datagram.client_endpoint, proxy::InboundDatagramCheck::Commit)) {
            return;
        }
        session->UpdateReplyEndpoint(datagram.client_endpoint);
        if (auto* hook = session->association_hook_) {
            hook->last_active = now;
        }
        (void)session->Push(decoded.target, std::move(decoded.payload));
        return;
    }
    if (!record->association->Check(*decoded.packet_id, datagram.worker_id,
            datagram.client_endpoint, proxy::InboundDatagramCheck::Commit)) {
        return;
    }
    ProcessDecoded(datagram, std::move(decoded), now, std::move(record));
}

// What a claim holds while the coordinator decides which Worker runs the
// session: the datagrams that arrived meanwhile, and what creating the
// session here needs once the synchronous decode views are gone.
struct UdpIngress::PendingSessionClaim {
    struct Datagram {
        udp::endpoint client;
        uint64_t packet_id = 0;
        common::TargetAddress target;
        common::MultiBuffer payload;
        std::optional<common::ForwardedMetadata> forwarded;
        // The Worker that received it.
        uint32_t source = 0;
    };

    SocketStatePtr socket;
    DatagramSessionEnvironment environment;
    const proxy::InboundDatagramAssociationPolicy* policy = nullptr;
    common::UserProfile profile;
    uint32_t worker_id = 0;
    uint64_t token = 0;
    common::RingDeque<Datagram> datagrams;

    void Queue(Datagram datagram) {
        if (datagrams.size() < kMaxPendingClaimDatagrams) datagrams.push_back(std::move(datagram));
    }
};

bool UdpIngress::RouteSessionDatagram(const UdpDatagramContext& datagram,
    const UdpHandoffIdentity& identity, proxy::InboundDatagramResult& decoded) {
    // A session this Worker runs takes its datagrams here.
    if (const auto* record = handoff_directory_.Find(identity)) {
        if (const auto session = record->session.lock(); session && !session->Closed()) {
            return false;
        }
    }
    if (const auto route = remote_routes_.find(identity); route != remote_routes_.end()) {
        if (common::SetUdpTarget(decoded.payload, decoded.target)) {
            relay_->Forward(route->second.owner.worker, route->second.owner.token,
                            *decoded.packet_id, datagram.client_endpoint,
                            std::move(decoded.payload));
        }
        return true;
    }
    if (const auto pending = pending_claims_.find(identity); pending != pending_claims_.end()) {
        pending->second->Queue(PendingSessionClaim::Datagram{
            .client = datagram.client_endpoint, .packet_id = *decoded.packet_id,
            .target = std::move(decoded.target), .payload = std::move(decoded.payload),
            .forwarded = std::move(decoded.forwarded), .source = relay_->Index()});
        return true;
    }
    StartSessionClaim(datagram, identity, decoded);
    return true;
}

void UdpIngress::StartSessionClaim(const UdpDatagramContext& datagram,
    const UdpHandoffIdentity& identity, proxy::InboundDatagramResult& decoded) {
    if (pending_claims_.size() >= kMaxPendingSessionClaims || !datagram.environment.admission) {
        return;
    }
    auto claim = std::make_unique<PendingSessionClaim>();
    claim->socket = datagram.socket->shared_from_this();
    claim->environment = datagram.environment;
    claim->policy = decoded.association_policy;
    claim->profile = *decoded.user;
    claim->worker_id = datagram.worker_id;
    claim->Queue(PendingSessionClaim::Datagram{
        .client = datagram.client_endpoint, .packet_id = *decoded.packet_id,
        .target = std::move(decoded.target), .payload = std::move(decoded.payload),
        .forwarded = std::move(decoded.forwarded), .source = relay_->Index()});
    const auto key = NativeSessionOwnerKey(*datagram.socket, identity.client);
    auto& coordinator = datagram.environment.admission->coordinator;
    const auto [entry, inserted] = pending_claims_.try_emplace(identity, std::move(claim));
    if (!inserted) return;
    auto& pending = *entry->second;
    // Other Workers may learn this token from the directory before the claim
    // returns here; their datagrams then join the queue above.
    pending.token = relay_->ReserveToken(*this);
    try {
        owned_tokens_.try_emplace(pending.token, OwnedToken{.pending = &pending, .session = {}});
        ++session_claims_;
        try {
            net::co_spawn(io_context_,
                RunSessionClaim(identity, key, pending.token, coordinator),
                [this](std::exception_ptr) {
                    --session_claims_;
                    NotifyCompletion();
                });
        } catch (...) {
            --session_claims_;
            throw;
        }
    } catch (...) {
        owned_tokens_.erase(pending.token);
        relay_->ReleaseToken(pending.token);
        pending_claims_.erase(entry);
        throw;
    }
}

net::awaitable<void> UdpIngress::RunSessionClaim(UdpHandoffIdentity identity,
    SessionOwnerKey key, uint64_t token, GroupCoordinator& coordinator) {
    SessionClaim claim;
    try {
        claim = co_await ClaimSessionOwner(coordinator, key, SessionOwner{relay_->Index(), token});
    } catch (...) {
        // Without the directory the session cannot be shared: it runs here,
        // unannounced, as with a single Worker.
        claim = SessionClaim{.owner = SessionOwner{relay_->Index(), token}, .ownership = {}};
    }
    ResolveSessionClaim(identity, std::move(claim));
}

void UdpIngress::ResolveSessionClaim(const UdpHandoffIdentity& identity, SessionClaim claim) {
    const auto found = pending_claims_.find(identity);
    if (found == pending_claims_.end()) return;
    auto pending = std::move(found->second);
    pending_claims_.erase(found);
    common::MaybeShrinkHashContainer(pending_claims_);
    const uint64_t token = pending->token;
    const bool owned_here = claim.owner.worker == relay_->Index();
    const auto release_token = [&]() noexcept {
        owned_tokens_.erase(token);
        relay_->ReleaseToken(token);
    };
    if (state_ != State::Running || !OwnsSocket(*pending->socket)) {
        release_token();
        return;
    }
    if (!owned_here) {
        // Nobody learned this token: the directory named another owner.
        release_token();
        AddRemoteRoute(identity, claim.owner);
        while (!pending->datagrams.empty()) {
            auto datagram = std::move(pending->datagrams.front());
            pending->datagrams.pop_front();
            if (!common::SetUdpTarget(datagram.payload, datagram.target)) continue;
            relay_->Forward(claim.owner.worker, claim.owner.token, datagram.packet_id,
                            datagram.client, std::move(datagram.payload));
        }
        return;
    }
    const auto* receiver = pending->environment.handler
        ? &pending->environment.handler->ReceiverSettings() : nullptr;
    if (!receiver || !pending->environment.prepared || !pending->environment.prepared->settings) {
        release_token();
        return;
    }
    std::shared_ptr<ClientSession> session;
    while (!pending->datagrams.empty()) {
        auto datagram = std::move(pending->datagrams.front());
        pending->datagrams.pop_front();
        const UdpDatagramContext context{
            .socket = pending->socket.get(),
            .client_endpoint = datagram.client,
            .payload = {},
            .receiver = receiver,
            .io_context = io_context_,
            .worker_id = pending->worker_id,
            .environment = pending->environment,
        };
        DeliverSessionDatagram(context, identity, proxy::InboundDatagramResult{
            .target = std::move(datagram.target),
            .payload = std::move(datagram.payload),
            .forwarded = std::move(datagram.forwarded),
            .session_id = identity.client.session_id,
            .session_owner = identity.client.owner,
            .packet_id = datagram.packet_id,
            .association_policy = pending->policy,
            .user = &pending->profile,
        }, std::chrono::steady_clock::now());
        if (!session) {
            const auto* record = handoff_directory_.Find(identity);
            session = record ? record->session.lock() : nullptr;
            if (!session || session->Closed()) {
                // Creation failed: datagrams of other Workers draw a Gone.
                session.reset();
                release_token();
                return;
            }
            if (claim.ownership) {
                session->relay_token_ = token;
                session->ownership_ = std::move(claim.ownership);
                owned_tokens_.insert_or_assign(token, OwnedToken{.pending = nullptr, .session = session});
            } else {
                // The directory was full: the session runs here unannounced.
                release_token();
            }
        }
        if (datagram.source != relay_->Index() && session->relay_token_ &&
            std::find(session->relay_sources_.begin(), session->relay_sources_.end(),
                      datagram.source) == session->relay_sources_.end()) {
            session->relay_sources_.push_back(datagram.source);
        }
    }
    if (!session) release_token();
}

void UdpIngress::ReceiveRelayedDatagram(uint32_t from, uint64_t token, uint64_t packet_id,
                                        const udp::endpoint& client,
                                        common::MultiBuffer payload) noexcept {
    const auto found = owned_tokens_.find(token);
    if (found == owned_tokens_.end()) {
        relay_->SendGone(from, token);
        return;
    }
    const auto datagram = common::InspectUdpDatagram(payload);
    if (!datagram.Valid()) return;
    try {
        common::TargetAddress target = *datagram.target;
        if (auto* pending = found->second.pending) {
            pending->Queue(PendingSessionClaim::Datagram{
                .client = client, .packet_id = packet_id, .target = std::move(target),
                .payload = std::move(payload), .forwarded = std::nullopt, .source = from});
            return;
        }
        const auto session = found->second.session.lock();
        if (!session || session->Closed() || !session->handoff_record_) {
            relay_->SendGone(from, token);
            return;
        }
        // The path rule of the association treats this Worker's socket as
        // the path, whichever Worker received the datagram.
        if (!session->handoff_record_->association->Check(packet_id, session->reply_.worker_id,
                client, proxy::InboundDatagramCheck::Commit)) {
            return;
        }
        if (auto* hook = session->association_hook_) {
            hook->last_active = std::chrono::steady_clock::now();
        }
        session->UpdateReplyEndpoint(client);
        if (std::find(session->relay_sources_.begin(), session->relay_sources_.end(), from) ==
            session->relay_sources_.end()) {
            session->relay_sources_.push_back(from);
        }
        (void)session->Push(target, std::move(payload));
    } catch (...) {
        // Allocation failure drops the datagram.
    }
}

void UdpIngress::AddRemoteRoute(const UdpHandoffIdentity& identity, SessionOwner owner) {
    if (const auto existing = remote_routes_.find(identity); existing != remote_routes_.end()) {
        const std::pair<uint32_t, uint64_t> old_key{
            existing->second.owner.worker, existing->second.owner.token};
        remote_route_keys_.erase(old_key);
        relay_->RemoveRoute(old_key.first, old_key.second);
        remote_routes_.erase(existing);
    }
    // Without room the datagrams of this session each claim again.
    if (remote_routes_.size() >= kMaxRemoteRoutes) return;
    const std::pair<uint32_t, uint64_t> key{owner.worker, owner.token};
    relay_->AddRoute(owner.worker, owner.token, *this);
    try {
        remote_route_keys_.try_emplace(key, identity);
        remote_routes_.try_emplace(identity, RemoteRoute{owner});
    } catch (...) {
        remote_route_keys_.erase(key);
        relay_->RemoveRoute(owner.worker, owner.token);
        throw;
    }
}

void UdpIngress::ForgetRemoteRoute(uint32_t owner, uint64_t token) noexcept {
    const auto found = remote_route_keys_.find({owner, token});
    if (found == remote_route_keys_.end()) return;
    remote_routes_.erase(found->second);
    remote_route_keys_.erase(found);
    common::MaybeShrinkHashContainer(remote_routes_);
    common::MaybeShrinkHashContainer(remote_route_keys_);
}

void UdpIngress::EraseRemoteRoutes(const SocketState& socket) noexcept {
    for (auto route = remote_routes_.begin(); route != remote_routes_.end();) {
        if (route->first.socket != &socket) {
            ++route;
            continue;
        }
        const std::pair<uint32_t, uint64_t> key{route->second.owner.worker,
                                                route->second.owner.token};
        remote_route_keys_.erase(key);
        if (relay_) relay_->RemoveRoute(key.first, key.second);
        route = remote_routes_.erase(route);
    }
}

void UdpIngress::ReleaseOwnedSession(ClientSession& session) noexcept {
    const uint64_t token = std::exchange(session.relay_token_, 0);
    session.ownership_.Release();
    if (!relay_) return;
    owned_tokens_.erase(token);
    relay_->ReleaseToken(token);
    for (const uint32_t source : session.relay_sources_) relay_->SendGone(source, token);
    session.relay_sources_.clear();
}

void UdpIngress::ProcessDecoded(const UdpDatagramContext& datagram,
    proxy::InboundDatagramResult result, std::chrono::steady_clock::time_point now,
    std::shared_ptr<UdpHandoffRecord> record) {
    auto* decoded = &result;
    auto& socket = *datagram.socket;

    auto client_key_log = [&]() {
        return common::TargetAddress(
            common::NormalizeAddress(datagram.client_endpoint.address()),
            datagram.client_endpoint.port());
    };
    const ClientSessionKey client_session_key{
        decoded->session_owner, decoded->session_id, datagram.client_endpoint,
        datagram.environment.prepared
            ? datagram.environment.prepared->settings.get() : nullptr};
    if (decoded->session_owner.size == 0) {
        LOG_NET_DEBUG(
            "UDP datagram rejected worker={} client={} > missing authenticated session owner",
            datagram.worker_id,
            client_key_log());
        return;
    }

    ClientSessionPtr current_session;
    {
        if (auto row = socket.sessions.find(client_session_key);
            row != socket.sessions.end()) {
            if (ShouldReclaim(
                    row->second, now, row->second.reclaim_hook.idle_timeout)) {
                ReclaimAssociation(row->second.reclaim_hook, now);
                // Synchronous cancellation may retire or replace the listener.
                // The decoded packet cannot create a request for its old socket.
                if (!OwnsSocket(socket)) return;
            } else if (row->second.link && !row->second.link->Closed()) {
                current_session = row->second.link;
                if (current_session->Owns(decoded->session_owner)) {
                    row->second.reclaim_hook.last_active = now;
                }
            }
        }
    }
    const bool need_new_session = !current_session;
    ClientSessionPtr packet_session = std::move(current_session);
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
        auto response = proxy_->CreateDatagramResponse(*decoded);
        if (!response || !*response) {
            LOG_NET_DEBUG("UDP response preparation failed worker={} client={}",
                          datagram.worker_id, client_key_log());
            return;
        }

        if (!OwnsSocket(socket) || state_ != State::Running) return;
        const auto local_endpoint = socket.local_endpoint;

        const uint32_t worker_id = datagram.worker_id;
        auto socket_pin = socket.shared_from_this();
        ReplyRoute reply{
            .socket = socket_pin,
            .response = std::move(*response),
            .owner = this,
            .worker_id = worker_id};
        auto client_session = CreateClientSession(
            socket_pin, client_session_key, datagram.io_context,
            std::move(reply), datagram.client_endpoint,
            decoded->session_owner, now, datagram.environment.timeouts.IdleTimeout(), record);
        if (!client_session) return;
        packet_session = client_session;
        preparation_session = client_session;
        if (state_ != State::Running ||
            !OwnsSocket(socket)) {
            client_session->Close();
            return;
        }
        if (record) {
            if (!OwnsSocket(socket)) return;
            socket.associations.insert_or_assign(
                proxy::InboundDatagramAssociationKey{decoded->session_owner, *decoded->session_id,
                    client_session_key.configuration},
                record->association.get());
        }
        client_session->request_.emplace(datagram.receiver->dispatch_policy);
        auto& request = *client_session->request_;
        auto& ctx = request.context;
        ctx.conn_id = common::NewID(datagram.worker_id);
        ctx.worker_id = datagram.worker_id;
        const std::string_view inbound_tag = datagram.receiver->inbound_tag.empty()
            ? std::string_view(tag_)
            : std::string_view(datagram.receiver->inbound_tag);
        ctx.inbound.tag.assign(inbound_tag);
        ctx.inbound.accounting_key.assign(datagram.receiver->accounting_key);
        if (const auto* route_tags = datagram.receiver->RouteInboundTags()) {
            ctx.inbound.tags.reserve(route_tags->size());
            for (const auto& route_tag : *route_tags)
                ctx.inbound.tags.emplace_back(route_tag);
        }
        const auto client_address =
            common::NormalizeAddress(datagram.client_endpoint.address());
        const common::AddressText client_ip(client_address);
        ctx.inbound.source_ip.assign(client_ip.View());
        ctx.inbound.source_addr = client_address;
        ctx.inbound.source_port = datagram.client_endpoint.port();
        ctx.inbound.local_endpoint = local_endpoint;
        request.profile = *decoded->user;
        const auto& env = datagram.environment;
        request.dispatcher = env.dispatcher;
        request.admission = env.admission;
        request.request_load = env.request_load;
        ::proxy::BindInboundRequestTarget(
            ctx,
            ::proxy::InboundRequestTarget{
                common::Network::UDP,
                decoded->target,
                std::move(decoded->forwarded)});
        request.io_context = &datagram.io_context;
        request.timeouts = env.timeouts;
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
                [this, client_session, worker_id](std::exception_ptr error) {
                    client_session->Close();
                    RetireNativeJob(*client_session);
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
    const SocketStatePtr& socket, udp::endpoint endpoint, common::MultiBuffer payload) {
    if (!socket || !OwnsSocket(*socket) || state_ != State::Running)
        return ReplyEnqueueResult::Rejected;
    const auto bytes = payload.byte_size();
    if (bytes == 0 || WouldOverflowUdpQueue(socket->pending.size(), socket->queued_bytes, bytes))
        return ReplyEnqueueResult::Rejected;
    auto reservation = budget_.ReservePayload(payload);
    if (!reservation) return ReplyEnqueueResult::Rejected;
    const bool start = !socket->sender_running && socket->active_id == 0;
    socket->pending.push_back(SocketState::QueuedReply{
        std::move(endpoint), std::move(payload), bytes, std::move(reservation)});
    socket->queued_bytes += bytes;
    return start ? ReplyEnqueueResult::StartSend : ReplyEnqueueResult::Queued;
}

std::optional<UdpIngress::PendingUdpReply> UdpIngress::CompleteReplySend(
    SocketState& socket, uint64_t id) {
    if (id == 0 || socket.active_id != id) return std::nullopt;
    socket.active_id = 0;
    socket.active_payload_size = 0;
    return BeginReplySend(socket);
}

void UdpIngress::ClearReplyQueue(SocketState& socket) noexcept {
    socket.pending.clear();
    socket.queued_bytes = 0;
    socket.active_id = 0;
    socket.active_payload_size = 0;
    for (auto* waiter : socket.reply_waiters) (void)waiter->reply_room_signal_.try_send(IoErrorCode{});
}

bool UdpIngress::SendReply(const SocketStatePtr& socket, udp::endpoint endpoint,
                          common::MultiBuffer payload, uint32_t worker_id) {
    const auto result = EnqueueReply(socket, std::move(endpoint), std::move(payload));
    if (result == ReplyEnqueueResult::Rejected) return false;
    if (result != ReplyEnqueueResult::StartSend) return true;
    socket->sender_running = true;
    ++reply_senders_;
    try {
        net::co_spawn(io_context_, SendUdpReplies(*this, socket, worker_id),
            [this, socket, worker_id](std::exception_ptr error) {
                socket->sender_running = false;
                --reply_senders_;
                if (error) {
                    ClearReplyQueue(*socket);
                    try {
                        try { std::rethrow_exception(error); }
                        catch (const std::exception& failure) {
                            LOG_ERROR("UDP reply sender failed worker={} > {}", worker_id, failure.what());
                        } catch (...) {
                            LOG_ERROR("UDP reply sender failed worker={} > unknown error", worker_id);
                        }
                    } catch (...) {}
                }
                NotifyCompletion();
            });
    } catch (...) {
        socket->sender_running = false;
        --reply_senders_;
        ClearReplyQueue(*socket);
        NotifyCompletion();
        throw;
    }
    return true;
}

net::awaitable<void> UdpIngress::SendUdpReplies(
    UdpIngress& ingress, SocketStatePtr socket, uint32_t worker_id) {
    auto packet = ingress.BeginReplySend(*socket);
    while (packet && ingress.OwnsSocket(*socket)) {
        auto [ec, bytes] = co_await socket->socket->async_send_to(
            packet->SendBuffers(), packet->endpoint, net::as_tuple(net::use_awaitable));
        if (ec || bytes != packet->payload.byte_size()) {
            ingress.ClearReplyQueue(*socket);
            if (ec && ec != net::error::operation_aborted)
                LOG_NET_DEBUG("UDP reply failed worker={} > {}", worker_id, ec.message());
            co_return;
        }
        packet = ingress.CompleteReplySend(*socket, packet->id);
    }
    ingress.ClearReplyQueue(*socket);
}

void UdpIngress::NotifyCompletion() noexcept {
    if (Busy()) return;
    if (state_ == State::Stopping) state_ = State::Drained;
    if (join_observers_ == 0) return;
    try {
        if (!completion_signal_.try_send(IoErrorCode{}))
            common::FailRuntime("udp-ingress-join", "completion channel full");
    } catch (...) {
        common::FailRuntime("udp-ingress-join", "completion signal failed");
    }
}

UdpIngress::ClientSessionPtr UdpIngress::CreateClientSession(
    const SocketStatePtr& socket, const ClientSessionKey& client_key,
    net::io_context& io_context, ReplyRoute reply, udp::endpoint reply_endpoint,
    proxy::InboundDatagramOwner owner, std::chrono::steady_clock::time_point last_active,
    std::chrono::seconds idle_timeout, std::shared_ptr<UdpHandoffRecord> record) {
    if (state_ != State::Running || !socket || !OwnsSocket(*socket) ||
        client_key.owner.size == 0 || !client_key.owner.Same(owner)) return nullptr;
    auto association = budget_.AcquireAssociation();
    if (!association) return nullptr;
    auto session = std::make_shared<ClientSession>(
        io_context, std::move(reply), std::move(reply_endpoint), std::move(owner),
        budget_, std::move(association), record);
    reclaimer_.ReserveRow();
    common::CheckTestAllocationFault();
    auto [row, inserted] = socket->sessions.try_emplace(client_key);
    auto previous = std::move(row->second.link);
    if (previous) previous->association_hook_ = nullptr;
    if (!inserted) SetLocalAssociation(row->second.reclaim_hook, nullptr);
    row->second.link = session;
    row->second.reclaim_hook.last_active = last_active;
    if (inserted) {
        Link(row->second, *socket, row->first, idle_timeout);
    } else {
        row->second.reclaim_hook.idle_timeout = idle_timeout;
        session->association_hook_ = &row->second.reclaim_hook;
        reclaimer_.Rearm(row->second.reclaim_hook, UdpAssociationExpiry(last_active, idle_timeout));
    }
    if (record) record->session = session;
    if (previous) previous->Close();
    return session;
}

void UdpIngress::ReclaimAssociation(
    UdpAssociationHook& hook, std::chrono::steady_clock::time_point now) noexcept {
    auto* socket = hook.socket;
    if (!socket) return;
    auto row = socket->sessions.find(*hook.client_key);
    if (row == socket->sessions.end() || &row->second.reclaim_hook != &hook) {
        reclaimer_.Unregister(hook);
        return;
    }
    if (!ShouldReclaim(row->second, now, hook.idle_timeout)) {
        reclaimer_.Rearm(hook, UdpAssociationExpiry(hook.last_active, hook.idle_timeout));
        return;
    }
    auto session = row->second.link;
    Unlink(row->second);
    socket->sessions.erase(row);
    common::MaybeShrinkHashContainer(socket->sessions);
    if (session) session->Close();
}

void UdpIngress::CleanupClientSessions(SocketState& socket) noexcept {
    for (auto& [key, row] : socket.sessions) {
        (void)key;
        Unlink(row);
    }
    decltype(socket.sessions) detached;
    detached.swap(socket.sessions);
    for (auto& [key, row] : detached) {
        (void)key;
        if (row.link) row.link->Close();
    }
}

void UdpIngress::CleanupAllClientSessions() noexcept {
    for (;;) {
        const auto found = std::find_if(sockets_.begin(), sockets_.end(),
            [](const auto& entry) { return !entry.second->sessions.empty(); });
        if (found == sockets_.end()) return;
        auto socket = found->second;
        CleanupClientSessions(*socket);
    }
}

UdpIngress::SocketStatePtr UdpIngress::AttachSocket(SocketPtr socket) {
    if (!socket || state_ != State::Running) return nullptr;
    for (const auto& [identity, state] : sockets_) {
        (void)identity;
        if (state->socket == socket) return nullptr;
    }
    auto state = std::make_shared<SocketState>();
    state->owner = this;
    state->socket = std::move(socket);
    IoErrorCode ec;
    const auto local = state->socket->local_endpoint(ec);
    if (!ec && !local.address().is_unspecified())
        state->local_endpoint.emplace(common::NormalizeAddress(local.address()), local.port());
    if (!ec) state->bound_endpoint = local;
    sockets_.emplace(state.get(), state);
    return state;
}

bool UdpIngress::OwnsSocket(const SocketState& socket) const noexcept {
    return socket.owner == this;
}

size_t UdpIngress::SocketCount() const noexcept { return sockets_.size(); }

void UdpIngress::CloseSocket(SocketState& socket) noexcept {
    auto found = sockets_.find(&socket);
    if (found == sockets_.end()) return;
    auto pin = std::move(found->second);
    sockets_.erase(found);
    socket.owner = nullptr;
    ClearReplyQueue(socket);
    IoErrorCode ec;
    socket.socket->cancel(ec);
    socket.socket->close(ec);
    CleanupClientSessions(socket);
    EraseRemoteRoutes(socket);
    CloseMatchingJobs([&socket](const ClientSession& job) noexcept {
        return job.reply_.socket.get() == &socket;
    });
}

template <typename Pred>
void UdpIngress::CloseMatchingJobs(Pred&& match) noexcept {
    ClientSession* notify = nullptr;
    for (auto* job = jobs_; job;) {
        auto* next = job->job_next_;
        if (match(*job)) {
            if (job->job_previous_) job->job_previous_->job_next_ = next;
            else jobs_ = next;
            if (next) next->job_previous_ = job->job_previous_;
            job->job_previous_ = nullptr;
            job->job_next_ = nullptr;
            job->job_linked_ = false;
            job->notification_pin_ = job->job_pin_.lock();
            job->notify_next_ = notify;
            notify = job;
        }
        job = next;
    }
    while (notify) {
        auto* current = notify;
        notify = current->notify_next_;
        current->notify_next_ = nullptr;
        auto session = std::move(current->notification_pin_);
        if (session) session->Close();
    }
}

UdpHandoffRecord* UdpHandoffDirectory::Find(const UdpHandoffIdentity& key) const noexcept {
    const auto found = records_.find(key);
    return found == records_.end() ? nullptr : found->second.get();
}

std::shared_ptr<UdpHandoffRecord> UdpHandoffDirectory::Claim(
    const UdpHandoffIdentity& key,
    std::shared_ptr<const PreparedInboundSettings> configuration,
    const proxy::InboundDatagramAssociationPolicy& policy) {
    using Clock = proxy::InboundDatagramAssociation::Clock;
    if (auto found = records_.find(key); found != records_.end()) {
        auto& record = found->second;
        if (&record->association->Policy() != &policy || record->association->claimed) return {};
        if (record->session.expired() &&
            record->association->ProtectedUntil() != Clock::time_point{} &&
            record->association->ProtectedUntil() < Clock::now()) {
            auto association = policy.create();
            record->association = std::move(association);
            record->configuration = std::move(configuration);
        }
        record->association->claimed = true;
        return record;
    }
    // 满表每次最多检查固定批次；游标跨请求续扫，绝不按包全表遍历。
    const auto now = Clock::now();
    const auto checks = std::min<std::size_t>(64, records_.size());
    for (std::size_t index = 0; records_.size() >= policy.capacity && cursor_ && index < checks; ++index) {
        auto* row = cursor_;
        cursor_ = row->next;
        if (row->association->claimed || !row->session.expired() ||
            row->association->ProtectedUntil() >= now) continue;
        if (row->next == row) cursor_ = nullptr;
        else {
            row->previous->next = row->next;
            row->next->previous = row->previous;
        }
        const auto* identity = std::exchange(row->identity, nullptr);
        row->previous = nullptr;
        row->next = nullptr;
        records_.erase(*identity);
    }
    if (records_.size() >= policy.capacity) return {};
    auto record = std::make_shared<UdpHandoffRecord>(policy);
    record->configuration = std::move(configuration);
    const auto [inserted, accepted] = records_.emplace(key, record);
    if (!accepted) throw std::logic_error("duplicate UDP handoff identity");
    record->identity = &inserted->first;
    if (!cursor_) {
        record->next = record.get();
        record->previous = record.get();
        cursor_ = record.get();
    } else {
        record->next = cursor_;
        record->previous = cursor_->previous;
        cursor_->previous->next = record.get();
        cursor_->previous = record.get();
    }
    return record;
}

}  // namespace app
