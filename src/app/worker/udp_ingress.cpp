#include "udp_ingress.hpp"
#include "app/proxyman/inbound/handler.hpp"
#include "common/awaitable_task_group.hpp"
#include "proxy/inbound_admission.hpp"

#include "common/initial_payload.hpp"
#include "common/ip_utils.hpp"
#include "common/session.hpp"
#include "common/allocator.hpp"
#include "common/container_util.hpp"
#include "common/string_hash.hpp"
#include "features/routing/dispatcher.hpp"
#include "infra/config_types.hpp"
#include "infra/log.hpp"
#include "transport/async_stream.hpp"

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

namespace worker_detail {

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
    TimeoutScheduler& scheduler,
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
    UdpAssociationHook& hook, UdpIngress& owner, std::string_view socket_key,
    const ClientSessionKey& client_key, std::chrono::seconds idle_timeout,
    TimePoint deadline) noexcept {
    if (stopped_) {
        FailRuntime("udp-maintenance", "association registered after reclaimer stop");
    }
    if (hook.owner) {
        FailRuntime("udp-maintenance", "association hook registered twice");
    }
    if (heap_.size() == heap_.capacity()) {
        FailRuntime("udp-maintenance", "association registered without reserved capacity");
    }
    hook.owner = &owner;
    hook.socket_key = socket_key;
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
        decltype(heap_)(heap_.get_allocator()).swap(heap_);
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
            FailRuntime("udp-maintenance", "association schedule refused after release");
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


}  // namespace

bool UdpIngress::ReplyRoute::Send(UDPPacketView packet, const udp::endpoint& endpoint) {
    auto payload = response->Encode(packet);
    if (payload.empty()) return false;
    return sink->EnqueueUdpReply(*owner, socket_key, socket, endpoint, std::move(payload), worker_id);
}

UdpIngress::ClientSession::ClientSession(
    net::io_context& io_context,
    ReplyRoute reply,
    udp::endpoint reply_endpoint,
    InboundDatagramOwner session_owner,
    UdpResourceBudget& budget,
    UdpResourceBudget::AssociationLease association,
    std::shared_ptr<UdpHandoffRecord> record)
    : association_(std::move(association))
    , budget_(&budget)
    , reader_signal_(io_context, 1)
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

transport::CancellationSource& UdpIngress::ClientSession::Cancellation() noexcept {
    return cancellation_;
}

bool UdpIngress::ClientSession::Closed() const noexcept {
    return closed_;
}

bool UdpIngress::ClientSession::Owns(
    const InboundDatagramOwner& owner) const noexcept {
    return session_owner_.Same(owner);
}

void UdpIngress::ClientSession::UpdateReplyEndpoint(
    udp::endpoint endpoint) noexcept {
    reply_endpoint_ = std::move(endpoint);
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
            input_queue_.size(), queued_bytes_, payload_size)) {
        payload.clear();
        CloseWithError(ErrorCode::RESOURCE_EXHAUSTED);
        return false;
    }

    if (!buf::SetUdpTarget(payload, target)) return false;
    auto reservation = budget_->ReservePayload(payload);
    if (!reservation) return false;

    QueuedInput input{std::move(payload), payload_size, std::move(reservation)};
    input_queue_.push_back(std::move(input));
    queued_bytes_ += payload_size;
    WakeReader();
    return true;
}

void UdpIngress::ClientSession::Close() noexcept {
    CloseWithError(ErrorCode::OK);
}

net::awaitable<buf::MultiBuffer>
UdpIngress::ClientSession::ReadMultiBuffer() {
    while (true) {
        if (!input_queue_.empty()) {
            auto input = std::move(input_queue_.front());
            queued_bytes_ -= std::min(queued_bytes_, input.bytes);
            input_queue_.pop_front();
            co_return std::move(input.payload);
        }

        if (closed_) {
            if (terminal_error_ == ErrorCode::RESOURCE_EXHAUSTED) {
                throw IoSystemError(
                    io_error::no_buffer_space,
                    "UDP client input queue full");
            }
            if (terminal_error_ != ErrorCode::OK) {
                throw transport::LinkError(terminal_error_);
            }
            co_return buf::MultiBuffer{};
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
UdpIngress::ClientSession::WriteMultiBuffer(buf::MultiBuffer mb) {
    if (Closed() || !reply_.Valid()) {
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

    const buf::ContiguousBufferView payload(mb);
    if (!reply_.Send(UDPPacketView{*datagram.target, payload.Bytes()}, reply_endpoint_)) {
        mb.clear();
        throw IoSystemError(
            io_error::fault, "UDP client reply was rejected");
    }
    mb.clear();
    co_return;
}

std::optional<UdpIngress::PendingUdpReply> UdpIngress::BeginReplySend(
    ReplyQueueState& queue) {
    if (queue.active_id != 0 || queue.pending.empty()) return std::nullopt;
    if (last_reply_id_ == std::numeric_limits<uint64_t>::max())
        throw IoSystemError(io_error::no_buffer_space, "UDP reply send generation exhausted");

    // Describe the payload while it is still queued: a scatter spill is the
    // only fallible step, so failure leaves the queue untouched. Ordinary
    // packets move straight into their sender's frame without a heap node.
    auto& front = queue.pending.front();
    std::optional<PendingUdpReply> packet{std::in_place};
    packet->send_buffers.AppendMultiBuffer(front.payload);
    packet->id = ++last_reply_id_;
    packet->endpoint = std::move(front.endpoint);
    packet->payload = std::move(front.payload);
    packet->reservation = std::move(front.reservation);
    const size_t payload_size = front.payload_size;
    queue.queued_bytes -= payload_size;
    queue.pending.pop_front();
    queue.active_id = packet->id;
    queue.active_payload_size = payload_size;
    return packet;
}

void UdpIngress::Link(UdpClientSession& row, std::string_view socket_key,
                      const ClientSessionKey& client_key, std::chrono::seconds idle_timeout) noexcept {
    reclaimer_.Register(row.reclaim_hook, *this, socket_key, client_key, idle_timeout,
                        UdpAssociationExpiry(row.reclaim_hook.last_active, idle_timeout));
    row.link->association_hook_ = &row.reclaim_hook;
}

void UdpIngress::SetLocalAssociation(const UdpAssociationHook& hook,
                                     InboundDatagramAssociation* association) noexcept {
    if (!hook.client_key || !hook.client_key->session_id) return;
    auto socket = udp_sockets_.find(hook.socket_key);
    if (socket == udp_sockets_.end()) return;
    const auto& key = *hook.client_key;
    auto entry = socket->second.associations.find(
        InboundDatagramAssociationKey{key.owner, *key.session_id, key.configuration});
    if (entry != socket->second.associations.end()) entry->second = association;
}

void UdpIngress::Unlink(UdpClientSession& row) noexcept {
    const auto& hook = row.reclaim_hook;
    if (hook.client_key && hook.client_key->session_id) {
        auto socket = udp_sockets_.find(hook.socket_key);
        if (socket != udp_sockets_.end()) {
            const auto& key = *hook.client_key;
            socket->second.associations.erase(
                InboundDatagramAssociationKey{key.owner, *key.session_id, key.configuration});
        }
    }
    reclaimer_.Unregister(row.reclaim_hook);
    if (row.link) row.link->association_hook_ = nullptr;
}

void UdpIngress::ClientSession::CloseWithError(ErrorCode error) noexcept {
    if (closed_) {
        return;
    }
    closed_ = true;
    terminal_error_ = error;
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
    std::unique_ptr<::Inbound> proxy,
    UdpAssociationReclaimer& reclaimer,
    UdpResourceBudget& budget,
    net::io_context& io_context)
    : tag_(tag)
    , proxy_(std::move(proxy))
    , reclaimer_(reclaimer)
    , budget_(budget)
    , completion_signal_(io_context, 1) {}

UdpIngress::~UdpIngress() noexcept {
    if (outstanding_jobs_ != 0) {
        FailRuntime("udp-ingress", "destroyed with native dispatch jobs outstanding");
    }
    CleanupAllClientSessions();
}

UdpIngress::ResourceStats UdpIngress::GetResourceStats() const noexcept {
    ResourceStats stats{};
    for (const auto& [socket_key, sessions] : client_sessions_) {
        (void)socket_key;
        for (const auto& [client_key, session] : sessions) {
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
    }
    stats.native_dispatches = outstanding_jobs_;
    for (const auto& [socket_key, queue] : reply_queues_) {
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
    proxy_ = std::move(proxy);
    return true;
}

void UdpIngress::RequestStop() noexcept {
    if (state_ != State::Running) return;
    state_ = State::Stopping;
    while (!udp_sockets_.empty()) {
        CloseSocket(udp_sockets_.begin()->first);
    }
    CleanupAllClientSessions();
    reply_queues_.clear();

    ClientSession* notify = jobs_;
    jobs_ = nullptr;
    for (auto* job = notify; job;) {
        auto* next = job->job_next_;
        job->notification_pin_ = job->job_pin_.lock();
        job->notify_next_ = next;
        job->job_previous_ = nullptr;
        job->job_next_ = nullptr;
        job->job_linked_ = false;
        job = next;
    }
    while (notify) {
        auto* current = notify;
        notify = current->notify_next_;
        current->notify_next_ = nullptr;
        auto pin = std::move(current->notification_pin_);
        if (pin) pin->Close();
    }
    if (outstanding_jobs_ == 0) state_ = State::Drained;
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
            while (outstanding_jobs_ != 0) {
                auto [ec] = co_await completion_signal_.async_receive(
                    net::as_tuple(asio::bind_cancellation_slot(
                        asio::cancellation_slot{}, net::use_awaitable)));
                if (ec && outstanding_jobs_ != 0)
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
        FailRuntime("udp-ingress", "native dispatch completion underflow");
    }
    --outstanding_jobs_;
    if (state_ == State::Stopping && outstanding_jobs_ == 0)
        state_ = State::Drained;
    if (join_observers_ != 0 && outstanding_jobs_ == 0) {
        try {
            if (!completion_signal_.try_send(IoErrorCode{}))
                FailRuntime("udp-ingress-join", "completion event channel was full");
        } catch (...) {
            FailRuntime("udp-ingress-join", "failed to signal native job drain");
        }
    }
}

void UdpIngress::RetireNativeJob(ClientSession& session) noexcept {
    DetachNativeJob(session);
    session.job_pin_.reset();
    session.request_.reset();
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
        !datagram.sock || datagram.payload.empty()) {
        return;
    }
    if (!datagram.receiver) {
        LOG_NET_DEBUG(
            "UDP datagram rejected worker={} tag={} > missing prepared receiver",
            datagram.worker_id,
            tag_);
        return;
    }

    const std::string_view socket_key = datagram.socket_key;
    const auto socket = udp_sockets_.find(socket_key);
    if (socket == udp_sockets_.end() || socket->second.socket.get() != datagram.sock) return;
    const auto now = std::chrono::steady_clock::now();

    const auto normalized_client_addr =
        iputil::NormalizeAddress(datagram.client_endpoint.address());
    auto decoded = proxy_->Process(InboundDatagramRequest{
        .tag = tag_,
        .payload = datagram.payload,
        .associations = &socket->second.associations,
        .configuration = datagram.environment.prepared
            ? datagram.environment.prepared->settings.get() : nullptr,
        .worker_id = datagram.worker_id,
        .client_endpoint = datagram.client_endpoint,
    });
    if (!decoded) {
        if (decoded.error() == ErrorCode::PROTOCOL_AUTH_FAILED) {
            // Datagram sources are socket peers, never PROXY protocol clients,
            // so a credential failure is logged without feeding the ban table.
            session::Context rejected;
            rejected.worker_id = datagram.worker_id;
            rejected.inbound.tag = tag_;
            rejected.inbound.source_addr = normalized_client_addr;
            rejected.inbound.source_ip = iputil::AddressText(normalized_client_addr).View();
            rejected.inbound.source_port = datagram.client_endpoint.port();
            rejected.content.network = Network::UDP;
            ::proxy::LogInboundAuthFailure(
                rejected, "datagram authentication or validation failed");
        }
        return;
    }
    if (decoded->association_policy && decoded->session_id && decoded->packet_id) {
        const auto& prepared = datagram.environment.prepared;
        if (!prepared || !prepared->settings) return;
        if (decoded->committed_association) {
            const ClientSessionKey key{decoded->session_owner, decoded->session_id, {},
                                       prepared->settings.get()};
            if (auto outer = client_sessions_.find(socket_key);
                outer != client_sessions_.end()) {
                auto row = outer->second.find(key);
                if (row != outer->second.end() && row->second.link) {
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
        UdpHandoffIdentity identity{
            memory::String(socket_key), memory::String(tag_),
            prepared->settings.get(),
            ClientSessionKey{decoded->session_owner, decoded->session_id, {},
                             prepared->settings.get()}};
        auto record = UdpHandoffDirectory::Claim(
            handoff_records_, identity, prepared->settings,
            *decoded->association_policy);
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
            if (auto* hook = session->association_hook_) {
                hook->last_active = now;
            }
            (void)session->Push(decoded->target, std::move(decoded->payload));
            return;
        }
        if (!record->association->Check(*decoded->packet_id, datagram.worker_id,
                datagram.client_endpoint, InboundDatagramCheck::Commit)) {
            return;
        }
        ProcessDecoded(datagram, normalized_client_addr, std::move(*decoded), now, std::move(record));
        return;
    }
    ProcessDecoded(datagram, normalized_client_addr, std::move(*decoded), now);
}

void UdpIngress::ProcessDecoded(const UdpDatagramContext& datagram,
    const net::ip::address& client_address,
    InboundDatagramResult result, std::chrono::steady_clock::time_point now,
    std::shared_ptr<UdpHandoffRecord> record) {
    auto* decoded = &result;
    const auto socket_key = datagram.socket_key;

    auto client_key_log = [&]() {
        return TargetAddress(client_address, datagram.client_endpoint.port());
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
    if (auto outer = client_sessions_.find(socket_key);
        outer != client_sessions_.end()) {
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

        const auto sock_it = udp_sockets_.find(socket_key);
        if (sock_it == udp_sockets_.end() ||
            sock_it->second.socket.get() != datagram.sock ||
            state_ != State::Running) {
            return;
        }
        auto stable_socket = sock_it->second.socket;
        // Copied out: session creation may re-enter CloseSocket and erase the row.
        const auto local_endpoint = sock_it->second.local_endpoint;

        const uint32_t worker_id = datagram.worker_id;
        ReplyRoute reply{
            .socket_key = memory::String{socket_key},
            .socket = stable_socket,
            .response = std::move(*response),
            .sink = &datagram.reply_sink,
            .worker_id = worker_id,
            .owner = this};
        auto client_session = CreateClientSession(
            socket_key, client_session_key, datagram.io_context,
            std::move(reply), datagram.client_endpoint,
            decoded->session_owner, now, datagram.environment.timeouts.IdleTimeout(), record);
        if (!client_session) return;
        packet_session = client_session;
        preparation_session = client_session;
        if (state_ != State::Running ||
            !OwnsSocket(socket_key, stable_socket.get())) {
            client_session->Close();
            return;
        }
        if (record) {
            auto socket = udp_sockets_.find(socket_key);
            if (socket == udp_sockets_.end() ||
                socket->second.socket.get() != datagram.sock) return;
            socket->second.associations.insert_or_assign(
                InboundDatagramAssociationKey{decoded->session_owner, *decoded->session_id,
                    client_session_key.configuration},
                record->association.get());
        }
        client_session->request_.emplace(datagram.receiver->dispatch_policy);
        auto& request = *client_session->request_;
        auto& ctx = request.context;
        ctx.conn_id = session::NewID(datagram.worker_id);
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
        const iputil::AddressText client_ip(client_address);
        ctx.inbound.source_ip.assign(client_ip.View());
        ctx.inbound.source_addr = client_address;
        ctx.inbound.source_port = datagram.client_endpoint.port();
        ctx.inbound.local_endpoint = local_endpoint;
        request.profile = *decoded->user;
        const auto& env = datagram.environment;
        request.dispatcher = env.dispatcher;
        request.stats = env.stats;
        request.limiter = env.limiter;
        request.tracker = env.tracker;
        request.active_sessions = env.active_sessions;
        ::proxy::BindAuthenticatedInbound(
            ctx, request.profile,
            ::proxy::InboundRequestTarget{
                Network::UDP,
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
    std::string_view socket_key,
    udp::endpoint endpoint,
    buf::MultiBuffer payload) {
    const size_t payload_size = payload.byte_size();
    if (payload_size == 0 || payload_size > kMaxQueuedUdpBytes) {
        return ReplyEnqueueResult::Rejected;
    }
    auto queue_it = reply_queues_.find(socket_key);
    if (queue_it != reply_queues_.end() &&
        WouldOverflowUdpQueue(queue_it->second.pending.size(), queue_it->second.queued_bytes, payload_size)) {
        return ReplyEnqueueResult::Rejected;
    }
    auto reservation = budget_.ReservePayload(payload);
    if (!reservation) return ReplyEnqueueResult::Rejected;

    if (queue_it == reply_queues_.end()) {
        queue_it = reply_queues_.try_emplace(memory::String(socket_key)).first;
    }
    auto& queue = queue_it->second;
    const bool should_start_send = queue.active_id == 0;

    queue.pending.push_back(QueuedUdpReply{
        .endpoint = std::move(endpoint),
        .payload = std::move(payload),
        .payload_size = payload_size,
        .reservation = std::move(reservation)});
    queue.queued_bytes += payload_size;
    return should_start_send
        ? ReplyEnqueueResult::StartSend
        : ReplyEnqueueResult::Queued;
}

std::optional<UdpIngress::PendingUdpReply>
UdpIngress::BeginReplySend(std::string_view socket_key) {
    auto it = reply_queues_.find(socket_key);
    if (it == reply_queues_.end()) return std::nullopt;
    return BeginReplySend(it->second);
}

std::optional<UdpIngress::PendingUdpReply>
UdpIngress::CompleteReplySend(
    std::string_view socket_key,
    uint64_t completed_id) {
    auto it = reply_queues_.find(socket_key);
    if (it == reply_queues_.end()) {
        return std::nullopt;
    }

    auto& queue = it->second;
    if (completed_id == 0 || queue.active_id != completed_id) {
        return std::nullopt;
    }
    queue.active_id = 0;
    queue.active_payload_size = 0;
    return BeginReplySend(queue);
}

void UdpIngress::ClearReplyQueue(std::string_view socket_key) {
    const auto it = reply_queues_.find(socket_key);
    if (it != reply_queues_.end()) {
        reply_queues_.erase(it);
    }
    MaybeShrinkHashContainer(reply_queues_, 8);
}

UdpIngress::ClientSessionPtr UdpIngress::CreateClientSession(
    std::string_view socket_key,
    const ClientSessionKey& client_key,
    net::io_context& io_context,
    ReplyRoute reply,
    udp::endpoint reply_endpoint,
    InboundDatagramOwner session_owner,
    std::chrono::steady_clock::time_point last_active,
    std::chrono::seconds idle_timeout,
    std::shared_ptr<UdpHandoffRecord> record) {
    if (state_ != State::Running) return nullptr;
    if (client_key.owner.size == 0 || !client_key.owner.Same(session_owner)) return nullptr;
    auto association = budget_.AcquireAssociation();
    if (!association) return nullptr;
    auto session = std::make_shared<ClientSession>(
        io_context,
        std::move(reply),
        std::move(reply_endpoint),
        std::move(session_owner), budget_, std::move(association), record);
    if (record) record->session = session;
    reclaimer_.ReserveRow();
    auto [sessions_it, group_inserted] = FindOrEmplaceStringKey(
        client_sessions_, socket_key);
    auto& sessions = sessions_it->second;
    auto session_it = sessions.find(client_key);
    if (session_it == sessions.end()) {
        try {
            UdpClientSession candidate{.link = session, .reclaim_hook = {}};
            candidate.reclaim_hook.last_active = last_active;
            auto [inserted_it, inserted] = sessions.try_emplace(
                client_key, std::move(candidate));
            if (inserted) {
                Link(inserted_it->second, sessions_it->first, inserted_it->first,
                     idle_timeout);
            }
        } catch (...) {
            if (group_inserted) client_sessions_.erase(sessions_it);
            throw;
        }
    } else {
        auto& row = session_it->second;
        // The replaced session's closure must not mark the reused row due.
        auto previous = std::move(row.link);
        if (previous) previous->association_hook_ = nullptr;
        SetLocalAssociation(row.reclaim_hook, nullptr);
        row.link = session;
        row.reclaim_hook.last_active = last_active;
        row.reclaim_hook.idle_timeout = idle_timeout;
        session->association_hook_ = &row.reclaim_hook;
        reclaimer_.Rearm(row.reclaim_hook, UdpAssociationExpiry(last_active, idle_timeout));
        // Close may synchronously call CloseSocket and erase this replacement.
        // Do not access map iterators or key views after invoking it.
        if (previous) previous->Close();
    }
    return session;
}

void UdpIngress::ReclaimAssociation(
    UdpAssociationHook& hook,
    std::chrono::steady_clock::time_point now) noexcept {
    auto outer = client_sessions_.find(hook.socket_key);
    if (outer == client_sessions_.end()) {
        reclaimer_.Unregister(hook);
        return;
    }
    auto row = outer->second.find(*hook.client_key);
    if (row == outer->second.end() || &row->second.reclaim_hook != &hook) {
        reclaimer_.Unregister(hook);
        return;
    }
    if (!ShouldReclaim(row->second, now, hook.idle_timeout)) {
        // Uplink activity moved last_active without touching the heap.
        reclaimer_.Rearm(hook, UdpAssociationExpiry(row->second.reclaim_hook.last_active,
                                                    hook.idle_timeout));
        return;
    }
    auto session = row->second.link;
    const bool idle = session && !session->Closed() &&
        hook.idle_timeout.count() > 0 &&
        now - row->second.reclaim_hook.last_active > hook.idle_timeout;
    Unlink(row->second);
    outer->second.erase(row);
    // Release the last group before Close(): cancellation subscribers may
    // synchronously re-enter this ingress and erase the same socket key.
    if (outer->second.empty()) client_sessions_.erase(outer);
    if (idle) session->Close();
}

void UdpIngress::CleanupClientSessions(std::string_view socket_key) noexcept {
    auto sessions_it = client_sessions_.find(socket_key);
    if (sessions_it == client_sessions_.end()) {
        return;
    }

    for (auto& [client_key, session] : sessions_it->second) {
        (void)client_key;
        Unlink(session);
    }
    auto detached = client_sessions_.extract(sessions_it);
    for (auto& [client_key, session] : detached.mapped()) {
        (void)client_key;
        if (session.link) session.link->Close();
    }
}

void UdpIngress::CleanupAllClientSessions() noexcept {
    while (!client_sessions_.empty()) {
        CleanupClientSessions(client_sessions_.begin()->first);
    }
}

UdpIngress::SocketPtr UdpIngress::AttachSocket(
    std::string_view socket_key,
    SocketPtr socket) {
    if (!socket || state_ != State::Running) {
        return nullptr;
    }
    if (udp_sockets_.find(socket_key) != udp_sockets_.end()) {
        return nullptr;
    }
    std::optional<tcp::endpoint> local_endpoint;
    IoErrorCode local_ec;
    const auto local_ep = socket->local_endpoint(local_ec);
    if (!local_ec && !local_ep.address().is_unspecified()) {
        local_endpoint.emplace(iputil::NormalizeAddress(local_ep.address()), local_ep.port());
    }
    udp_sockets_.try_emplace(
        memory::String{socket_key},
        BoundSocket{
            .socket = socket,
            .local_endpoint = std::move(local_endpoint),
            .associations = {}});
    return socket;
}

UdpIngress::SocketPtr UdpIngress::FindSocket(
    std::string_view socket_key) noexcept {
    auto it = udp_sockets_.find(socket_key);
    return it == udp_sockets_.end() ? nullptr : it->second.socket;
}

bool UdpIngress::OwnsSocket(
    std::string_view socket_key,
    const udp::socket* socket) const noexcept {
    auto it = udp_sockets_.find(socket_key);
    return socket && it != udp_sockets_.end() &&
        it->second.socket.get() == socket;
}

size_t UdpIngress::SocketCount() const noexcept {
    return udp_sockets_.size();
}

void UdpIngress::CloseSocket(std::string_view socket_key) noexcept {
    // Find in every independent table before extraction can invalidate a key
    // view borrowed from any one of those tables.
    auto sessions_it = client_sessions_.find(socket_key);
    auto reply_it = reply_queues_.find(socket_key);
    auto sock_it = udp_sockets_.find(socket_key);
    SocketPtr socket_identity = sock_it == udp_sockets_.end()
        ? SocketPtr{} : sock_it->second.socket;

    ClientSession* notify = nullptr;
    for (auto* job = jobs_; job;) {
        auto* next = job->job_next_;
        if (socket_identity && job->reply_.socket == socket_identity) {
            if (job->job_previous_)
                job->job_previous_->job_next_ = next;
            else
                jobs_ = next;
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
    ClientSessionOuterMap::node_type detached_sessions;
    if (sessions_it != client_sessions_.end()) {
        for (auto& [client_key, session] : sessions_it->second) {
            (void)client_key;
            Unlink(session);
        }
        detached_sessions = client_sessions_.extract(sessions_it);
    }

    ReplyQueueMap::node_type detached_replies;
    if (reply_it != reply_queues_.end()) {
        detached_replies = reply_queues_.extract(reply_it);
    }

    UdpSocketMap::node_type detached_socket;
    if (sock_it != udp_sockets_.end()) {
        detached_socket = udp_sockets_.extract(sock_it);
    }

    while (notify) {
        auto* current = notify;
        notify = current->notify_next_;
        current->notify_next_ = nullptr;
        auto pin = std::move(current->notification_pin_);
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

}  // namespace worker_detail
