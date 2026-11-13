#include "app/udp_ingress.hpp"
#include "app/relay.hpp"
#include "app/inbound_handler.hpp"
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
    if (WouldOverflowUdpQueue(
            input_queue_.size(), queued_bytes_, payload_size)) {
        payload.clear();
        CloseWithError(common::ErrorCode::RESOURCE_EXHAUSTED);
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

net::awaitable<common::MultiBuffer>
UdpIngress::ClientSession::ReadMultiBuffer() {
    while (true) {
        if (!input_queue_.empty()) {
            auto input = std::move(input_queue_.front());
            queued_bytes_ -= std::min(queued_bytes_, input.bytes);
            input_queue_.pop_front();
            co_return std::move(input.payload);
        }

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

    if (!reply_.Send(proxy::UDPPacketView{*datagram.target, mb.FrontSpan()}, reply_endpoint_)) {
        mb.clear();
        throw IoSystemError(
            io_error::fault, "UDP client reply was rejected");
    }
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
    , completion_signal_(io_context, 1) {}

UdpIngress::~UdpIngress() noexcept {
    if (outstanding_jobs_ != 0 || reply_senders_ != 0) {
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
            while (outstanding_jobs_ != 0 || reply_senders_ != 0) {
                auto [ec] = co_await completion_signal_.async_receive(
                    net::as_tuple(asio::bind_cancellation_slot(
                        asio::cancellation_slot{}, net::use_awaitable)));
                if (ec && (outstanding_jobs_ != 0 || reply_senders_ != 0))
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
        admission = co_await AdmitNativeAssociation(*request.admission, request.context, std::move(bound));
        if (!admission || client_session->Closed()) {
            client_session->Close();
            co_return;
        }
        RelayResult result = co_await request.dispatcher->Dispatch(
            *request.io_context, request.policy, nullptr,
            transport::Link{client_session.get(), client_session.get()},
            common::InitialPayload{}, request.context, request.admission->stats, request.timeouts);
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

    const auto normalized_client_addr =
        common::NormalizeAddress(datagram.client_endpoint.address());
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
        if (decoded.error() == common::ErrorCode::PROTOCOL_AUTH_FAILED) {
            // Datagram sources are socket peers, never PROXY protocol clients,
            // so a credential failure is logged without feeding the ban table.
            common::Context rejected;
            rejected.worker_id = datagram.worker_id;
            rejected.inbound.tag = tag_;
            rejected.inbound.source_addr = normalized_client_addr;
            rejected.inbound.source_ip = common::AddressText(normalized_client_addr).View();
            rejected.inbound.source_port = datagram.client_endpoint.port();
            rejected.content.network = common::Network::UDP;
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
        UdpHandoffIdentity identity{
            &socket,
            ClientSessionKey{decoded->session_owner, decoded->session_id, {},
                             prepared->settings.get()}};
        auto record = handoff_directory_.Claim(
            identity, prepared->settings, *decoded->association_policy);
        if (!record) return;
        record->socket_pin = socket.shared_from_this();
        auto release_claim = MakeScopeExit([record]() noexcept {
            record->association->claimed = false;
        });
        if (auto session = record->session.lock()) {
            if (session->Closed() ||
                !record->association->Check(*decoded->packet_id, datagram.worker_id,
                    datagram.client_endpoint, proxy::InboundDatagramCheck::Commit)) {
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
                datagram.client_endpoint, proxy::InboundDatagramCheck::Commit)) {
            return;
        }
        ProcessDecoded(datagram, normalized_client_addr, std::move(*decoded), now, std::move(record));
        return;
    }
    ProcessDecoded(datagram, normalized_client_addr, std::move(*decoded), now);
}

void UdpIngress::ProcessDecoded(const UdpDatagramContext& datagram,
    const net::ip::address& client_address,
    proxy::InboundDatagramResult result, std::chrono::steady_clock::time_point now,
    std::shared_ptr<UdpHandoffRecord> record) {
    auto* decoded = &result;
    auto& socket = *datagram.socket;

    auto client_key_log = [&]() {
        return common::TargetAddress(client_address, datagram.client_endpoint.port());
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
    if (outstanding_jobs_ != 0 || reply_senders_ != 0) return;
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
