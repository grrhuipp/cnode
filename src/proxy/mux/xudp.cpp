#include "proxy/mux/xudp.hpp"

#include "app/inbound_handler.hpp"
#include "common/allocator.hpp"
#include "common/awaitable_task_group.hpp"
#include "common/hash.hpp"
#include "common/session.hpp"
#include "infra/config_types.hpp"
#include "infra/log.hpp"
#include "proxy/inbound_admission.hpp"
#include "routing/dispatcher.hpp"
#include "transport/timeout_scheduler.hpp"

#include <asio/as_tuple.hpp>
#include <asio/this_coro.hpp>
#include <asio/use_awaitable.hpp>
#include <openssl/sha.h>

#include <algorithm>
#include <cstring>
#include <optional>
#include <string_view>
#include <utility>

namespace proxy {
namespace {

using XudpKey = app::SessionOwnerKey;

// Flows one Worker runs; beyond, sub-sessions dispatch as plain UDP.
constexpr size_t kMaxFlows = 16 * 1024;
// Uplink datagrams a flow holds for its outbound, and replies it holds while
// no sub-session is attached; beyond, datagrams drop.
constexpr size_t kMaxQueuedDatagrams = 256;
constexpr size_t kMaxQueuedBytes = 512 * 1024;
// Datagrams waiting for ring room toward one Worker; beyond, they drop.
constexpr size_t kMaxRelayBacklog = 1024;
// Concurrent attachments of this Worker's sub-sessions to remote flows.
constexpr size_t kMaxClientSlots = 64 * 1024;

// A Global ID is scoped by the inbound and the identity (ID, email) it
// reports for the authenticated user: another user cannot take a flow over.
// Users an inbound does not tell apart share one scope, as in Xray.
XudpKey MakeXudpKey(const common::Context& ctx, const XudpGlobalId& global_id) noexcept {
    constexpr std::string_view kNamespace = "cnode/xudp";
    const auto& inbound = ctx.inbound;
    const uint64_t tag_size = inbound.tag.size();
    const uint64_t email_size = inbound.user_email.size();
    SHA256_CTX context;
    SHA256_Init(&context);
    SHA256_Update(&context, kNamespace.data(), kNamespace.size());
    SHA256_Update(&context, &tag_size, sizeof(tag_size));
    SHA256_Update(&context, inbound.tag.data(), inbound.tag.size());
    SHA256_Update(&context, &inbound.user_id, sizeof(inbound.user_id));
    SHA256_Update(&context, &email_size, sizeof(email_size));
    SHA256_Update(&context, inbound.user_email.data(), inbound.user_email.size());
    SHA256_Update(&context, global_id.data(), global_id.size());
    XudpKey key;
    SHA256_Final(key.data(), &context);
    return key;
}

struct XudpKeyHash {
    [[nodiscard]] size_t operator()(const XudpKey& key) const noexcept {
        size_t hash;
        std::memcpy(&hash, key.data(), sizeof(hash));
        return hash;
    }
};

// A bounded queue of single-Buffer datagrams.
class DatagramQueue {
public:
    [[nodiscard]] static size_t Charge(const common::MultiBuffer& datagram) noexcept {
        return std::max<size_t>(datagram.byte_size(), common::Buffer::kSize);
    }
    [[nodiscard]] bool HasRoom(const common::MultiBuffer& datagram) const noexcept {
        return queue_.size() < kMaxQueuedDatagrams && Charge(datagram) <= kMaxQueuedBytes - bytes_;
    }
    [[nodiscard]] bool Push(common::MultiBuffer datagram) {
        if (!HasRoom(datagram)) return false;
        const size_t bytes = Charge(datagram);
        queue_.push_back(std::move(datagram));
        bytes_ += bytes;
        return true;
    }
    [[nodiscard]] bool Pop(common::MultiBuffer& datagram) noexcept {
        if (queue_.empty()) return false;
        datagram = std::move(queue_.front());
        queue_.pop_front();
        bytes_ -= std::min(bytes_, Charge(datagram));
        return true;
    }
    void Clear() noexcept {
        queue_.clear();
        bytes_ = 0;
    }

private:
    common::RingDeque<common::MultiBuffer> queue_;
    size_t bytes_ = 0;
};

// Waits on a frame-local channel until signalled or `cancellation` fires.
struct ChannelWait final : common::CancellationSubscription {
    explicit ChannelWait(common::SignalChannel& wake) noexcept : wake(wake) {}
    common::SignalChannel& wake;
    bool cancelled = false;

private:
    void OnCancellation(common::Cancellation) noexcept override {
        cancelled = true;
        (void)wake.try_send(IoErrorCode{});
    }
};

}  // namespace

class XudpSessionTable;

// One XUDP flow, run by the Worker that started it: the outbound dispatch of
// its first sub-session, kept across the sub-sessions that take it over.
class XudpSession final : public transport::MultiBufferReader,
                          public transport::MultiBufferWriter,
                          private transport::TimeoutEvent,
                          public std::enable_shared_from_this<XudpSession> {
public:
    XudpSession(const XudpDispatchEnvironment& environment, const common::Context& sub_ctx,
                const XudpKey& key, XudpRelay* relay, XudpSessionTable& table);
    ~XudpSession() noexcept override;

    common::CancellationSource& Cancellation() noexcept override { return cancellation_; }
    [[nodiscard]] bool Closed() const noexcept { return closed_; }

    // Starts the dispatch, owned by the Worker's flow table.
    void Start();
    void Close() noexcept;
    // io_context shutdown without a Worker stop: forgets every attachment
    // without calling it.
    void Abandon() noexcept {
        closed_ = true;
        local_ = nullptr;
        remote_.reset();
        TimeoutEvent::Cancel();
        ownership.Discard();
        token = 0;
    }

    void AttachLocal(XudpClient& client);
    void DetachLocal(XudpClient& client) noexcept;
    void AttachRemote(uint32_t from, uint32_t slot, uint32_t generation);
    void DetachRemote(uint32_t from, uint32_t slot, uint32_t generation) noexcept;
    void PushUplink(common::MultiBuffer datagram) noexcept;
    // A local carrier waits here instead of losing datagrams to a full
    // flow queue: the wait holds back its Mux connection. False once the
    // flow closed or `carrier` (the sub-session's) was cancelled.
    [[nodiscard]] net::awaitable<bool> AwaitUplinkRoom(
        const common::MultiBuffer& datagram, common::CancellationSource& carrier);
    // The common case of AwaitUplinkRoom, without its wait state.
    [[nodiscard]] bool UplinkReady(const common::MultiBuffer& datagram,
                                   const common::CancellationSource& carrier) const noexcept {
        return !closed_ && !carrier.Stopped() && uplink_.HasRoom(datagram);
    }

    net::awaitable<common::MultiBuffer> ReadMultiBuffer() override;
    net::awaitable<void> WriteMultiBuffer(common::MultiBuffer mb) override;
    net::awaitable<void> WriteBuffers(std::span<const net::const_buffer> buffers) override {
        return WriteBuffersAsMultiBuffer(buffers);
    }

    // Set by its creator once the directory names this Worker its owner.
    uint64_t token = 0;
    app::SessionOwnership ownership;

private:
    struct Remote {
        uint32_t from;
        uint32_t slot;
        uint32_t generation;
    };

    void OnTimeout() noexcept override { Close(); }
    net::awaitable<void> Run(std::shared_ptr<XudpSession> self);
    // Ends the current attachment from this side and starts the expiry.
    void ReleaseAttachment() noexcept;
    void Unattached() noexcept;
    void Deliver(common::MultiBuffer datagram) noexcept;
    void WakeReader() noexcept { (void)reader_signal_.try_send(IoErrorCode{}); }
    void WakeCarrier() noexcept { (void)room_signal_.try_send(IoErrorCode{}); }

    net::io_context& io_context_;
    routing::Dispatcher& dispatcher_;
    routing::DispatchPolicy policy_;
    const app::AdmissionEnvironment& admission_;
    app::StatsShard& stats_;
    infra::TimeoutsConfig timeouts_;
    common::Context ctx_;
    XudpKey key_;
    XudpRelay* relay_;
    XudpSessionTable& table_;
    common::SignalChannel reader_signal_;
    common::SignalChannel room_signal_;
    // Woken when the attached sub-session may take a held-back reply.
    common::SignalChannel reply_room_signal_;
    common::CancellationSource cancellation_;
    DatagramQueue uplink_;
    // Replies held while no sub-session is attached.
    DatagramQueue parked_;
    XudpClient* local_ = nullptr;
    std::optional<Remote> remote_;
    bool closed_ = false;
};

// The flows of one Worker, and the tasks running them.
class XudpSessionTable final : public net::execution_context::service {
public:
    static net::execution_context::id id;
    explicit XudpSessionTable(net::execution_context& context)
        : net::execution_context::service(context) {}

    [[nodiscard]] std::shared_ptr<XudpSession> Find(const XudpKey& key) const {
        const auto found = sessions_.find(key);
        return found == sessions_.end() ? nullptr : found->second;
    }
    [[nodiscard]] bool Full() const noexcept { return sessions_.size() >= kMaxFlows; }
    [[nodiscard]] bool Stopping() const noexcept { return stopping_; }

    void Insert(const XudpKey& key, std::shared_ptr<XudpSession> session) {
        sessions_.insert_or_assign(key, std::move(session));
    }
    void Erase(const XudpKey& key, const XudpSession* session) noexcept {
        const auto found = sessions_.find(key);
        if (found == sessions_.end() || found->second.get() != session) return;
        sessions_.erase(found);
        common::MaybeShrinkHashContainer(sessions_);
    }

    void Spawn(net::any_io_executor executor, net::awaitable<void> task,
               common::CancellationSource& cancellation) {
        if (stopping_) throw IoSystemError(io_error::operation_aborted);
        if (!tasks_) tasks_.emplace(std::move(executor));
        tasks_->Spawn(std::move(task), &cancellation);
    }

    void RequestStop() noexcept {
        stopping_ = true;
        std::vector<std::shared_ptr<XudpSession>> open;
        try {
            open.reserve(sessions_.size());
            for (const auto& [key, session] : sessions_) {
                (void)key;
                open.push_back(session);
            }
        } catch (...) {
            // Without room for the snapshot, close them in place.
            while (!sessions_.empty()) sessions_.begin()->second->Close();
            return;
        }
        for (const auto& session : open) session->Close();
    }

    net::awaitable<void> Join() {
        stopping_ = true;
        if (tasks_) {
            co_await tasks_->AsyncJoin();
            tasks_.reset();
        }
    }

private:
    void shutdown() override {
        // Reached only without a Worker stop: the sub-sessions a flow points
        // to may be gone, so flows are dropped without calling them.
        auto sessions = std::move(sessions_);
        sessions_.clear();
        for (auto& [key, session] : sessions) {
            (void)key;
            session->Abandon();
        }
        sessions.clear();
        tasks_.reset();
    }

    std::unordered_map<XudpKey, std::shared_ptr<XudpSession>, XudpKeyHash> sessions_;
    std::optional<common::ResidentTaskGroup> tasks_;
    bool stopping_ = false;
};

net::execution_context::id XudpSessionTable::id;

XudpSession::XudpSession(const XudpDispatchEnvironment& environment,
                         const common::Context& sub_ctx, const XudpKey& key,
                         XudpRelay* relay, XudpSessionTable& table)
    : transport::TimeoutEvent(environment.io_context)
    , io_context_(environment.io_context)
    , dispatcher_(environment.dispatcher)
    , policy_(environment.policy)
    , admission_(environment.admission)
    , stats_(environment.stats)
    , timeouts_(environment.timeouts)
    , key_(key)
    , relay_(relay)
    , table_(table)
    , reader_signal_(environment.io_context, 1)
    , room_signal_(environment.io_context, 1)
    , reply_room_signal_(environment.io_context, 1) {
    ctx_.InitSubstreamFrom(sub_ctx);
    BindInboundRequestTarget(ctx_, InboundRequestTarget{
        common::Network::UDP, sub_ctx.outbound.target, std::nullopt});
}

XudpSession::~XudpSession() noexcept { Close(); }

void XudpSession::Start() {
    table_.Spawn(io_context_.get_executor(), Run(shared_from_this()), cancellation_);
}

net::awaitable<void> XudpSession::Run(std::shared_ptr<XudpSession> self) {
    try {
        InboundSubstreamAdmission admission(stats_);
        auto pending = InboundSubstreamAdmission::Reserve(admission_, ctx_);
        if (!pending || admission.Hold(co_await std::move(*pending), ctx_, stats_)) {
            // An XUDP sub-session is one Xray link, whatever its packets address.
            routing::DispatchRequest request{transport::Link{this, this}};
            request.udp_addressing = routing::UdpAddressing::SingleLink;
            (void)co_await DispatchAuthenticatedInbound(dispatcher_,
                io_context_, policy_, std::move(request), ctx_, stats_, timeouts_);
        }
    } catch (...) {
        LOG_CONN_DEBUG(ctx_, "XUDP flow dispatch failed with an exception");
    }
    self->Close();
}

void XudpSession::Close() noexcept {
    if (closed_) return;
    // The table may hold the last reference it drops below.
    const auto self = weak_from_this().lock();
    closed_ = true;
    TimeoutEvent::Cancel();
    cancellation_.Stop(common::ErrorCode::CANCELLED);
    uplink_.Clear();
    parked_.Clear();
    WakeReader();
    WakeCarrier();
    ReleaseAttachment();
    TimeoutEvent::Cancel();
    table_.Erase(key_, this);
    ownership.Release();
    if (relay_ && token != 0) relay_->ReleaseToken(std::exchange(token, 0));
}

void XudpSession::ReleaseAttachment() noexcept {
    if (auto* client = std::exchange(local_, nullptr)) {
        client->ForgetReplyRoom();
        client->Release();
    }
    (void)reply_room_signal_.try_send(IoErrorCode{});
    if (remote_) {
        const auto remote = *std::exchange(remote_, std::nullopt);
        relay_->ForgetAttachment(remote.from, remote.slot, remote.generation);
        relay_->SendDetached(remote.from, remote.slot, remote.generation);
    }
    Unattached();
}

void XudpSession::Unattached() noexcept {
    if (closed_) return;
    try {
        if (!ScheduleAfter(std::chrono::duration_cast<std::chrono::milliseconds>(kXudpExpiry))) {
            Close();
        }
    } catch (...) {
        Close();
    }
}

void XudpSession::AttachLocal(XudpClient& client) {
    ReleaseAttachment();
    TimeoutEvent::Cancel();
    local_ = &client;
    common::MultiBuffer datagram;
    while (parked_.Pop(datagram)) Deliver(std::move(datagram));
}

void XudpSession::DetachLocal(XudpClient& client) noexcept {
    if (local_ != &client) return;
    client.ForgetReplyRoom();
    local_ = nullptr;
    (void)reply_room_signal_.try_send(IoErrorCode{});
    Unattached();
}

void XudpSession::AttachRemote(uint32_t from, uint32_t slot, uint32_t generation) {
    relay_->BindAttachment(from, slot, generation, *this);
    ReleaseAttachment();
    TimeoutEvent::Cancel();
    remote_ = Remote{from, slot, generation};
    relay_->SendAttached(from, slot, generation);
    common::MultiBuffer datagram;
    while (parked_.Pop(datagram)) Deliver(std::move(datagram));
}

void XudpSession::DetachRemote(uint32_t from, uint32_t slot, uint32_t generation) noexcept {
    relay_->ForgetAttachment(from, slot, generation);
    if (!remote_ || remote_->from != from || remote_->slot != slot ||
        remote_->generation != generation) {
        return;
    }
    remote_.reset();
    Unattached();
}

net::awaitable<bool> XudpSession::AwaitUplinkRoom(
    const common::MultiBuffer& datagram, common::CancellationSource& carrier) {
    ChannelWait watch(room_signal_);
    watch.Resubscribe(carrier);
    while (!closed_ && !watch.cancelled && !uplink_.HasRoom(datagram)) {
        auto [error] = co_await room_signal_.async_receive(net::as_tuple(net::use_awaitable));
        if (error) co_return false;
    }
    co_return !closed_ && !watch.cancelled;
}

void XudpSession::PushUplink(common::MultiBuffer datagram) noexcept {
    if (closed_) return;
    try {
        if (uplink_.Push(std::move(datagram))) WakeReader();
    } catch (...) {
        // Allocation failure drops the datagram.
    }
}

void XudpSession::Deliver(common::MultiBuffer datagram) noexcept {
    try {
        if (local_) {
            (void)local_->PushReply(std::move(datagram));
        } else if (remote_) {
            relay_->SendReply(remote_->from, remote_->slot, remote_->generation,
                              std::move(datagram));
        } else {
            (void)parked_.Push(std::move(datagram));
        }
    } catch (...) {
        // Allocation failure drops the datagram.
    }
}

net::awaitable<common::MultiBuffer> XudpSession::ReadMultiBuffer() {
    for (;;) {
        common::MultiBuffer datagram;
        if (uplink_.Pop(datagram)) {
            WakeCarrier();
            co_return datagram;
        }
        if (closed_) co_return common::MultiBuffer{};
        auto [error] = co_await reader_signal_.async_receive(net::as_tuple(net::use_awaitable));
        if (error) throw IoSystemError(io_error::operation_aborted, "XUDP flow input cancelled");
    }
}

net::awaitable<void> XudpSession::WriteMultiBuffer(common::MultiBuffer mb) {
    if (closed_) {
        throw IoSystemError(io_error::operation_aborted, "XUDP flow closed");
    }
    const auto datagram = common::InspectUdpDatagram(mb);
    if (datagram.status == common::UdpDatagramStatus::Empty) co_return;
    if (!datagram.Valid()) {
        throw IoSystemError(io_error::invalid_argument,
                            "XUDP reply contains missing or mixed endpoints");
    }
    // Toward a sub-session of this Worker a reply waits for its Mux
    // connection's UDP budget, as Xray's XUDP writer blocks; toward another
    // Worker or while unattached it is relayed or held without waiting.
    for (;;) {
        if (closed_) throw IoSystemError(io_error::operation_aborted, "XUDP flow closed");
        auto* client = local_;
        if (!client) {
            Deliver(std::move(mb));
            co_return;
        }
        if (client->OfferReply(mb) != XudpReplyOffer::Full) co_return;
        client->AwaitReplyRoom(reply_room_signal_);
        auto [error] = co_await reply_room_signal_.async_receive(net::as_tuple(net::use_awaitable));
        // A client that left was told to forget this waker before it did.
        if (local_ == client) client->ForgetReplyRoom();
        if (error) throw IoSystemError(io_error::operation_aborted, "XUDP reply cancelled");
    }
}

// ---------------------------------------------------------------------------
// XudpRelay

size_t XudpRelay::AttachmentKeyHash::operator()(const AttachmentKey& key) const noexcept {
    return static_cast<size_t>(common::Mix64(
        (uint64_t{key.slot} << 32 | key.generation) ^ (uint64_t{key.from} << 56)));
}

XudpRelay::XudpRelay(net::io_context& io_context, std::shared_ptr<Mesh> mesh, size_t index)
    : endpoint_(*this, io_context, std::move(mesh), index) {}

XudpRelay::~XudpRelay() = default;

void XudpRelay::Stop() noexcept { endpoint_.Stop(); }

void XudpRelay::Shutdown() noexcept {
    endpoint_.Shutdown();
    tokens_.clear();
    attachments_.clear();
    for (auto& slot : slots_) {
        slot.client = nullptr;
        slot.wake = nullptr;
    }
}

uint32_t XudpRelay::Index() const noexcept { return static_cast<uint32_t>(endpoint_.Index()); }

uint64_t XudpRelay::ReserveToken(XudpSession& session) {
    const uint64_t token = ++next_token_;
    tokens_.emplace(token, &session);
    return token;
}

void XudpRelay::ReleaseToken(uint64_t token) noexcept {
    tokens_.erase(token);
    common::MaybeShrinkHashContainer(tokens_);
}

void XudpRelay::BindAttachment(uint32_t from, uint32_t slot, uint32_t generation,
                               XudpSession& session) {
    attachments_.insert_or_assign(AttachmentKey{from, slot, generation}, &session);
}

void XudpRelay::ForgetAttachment(uint32_t from, uint32_t slot, uint32_t generation) noexcept {
    attachments_.erase(AttachmentKey{from, slot, generation});
    common::MaybeShrinkHashContainer(attachments_);
}

// Owner -> client control messages are bounded by construction: one Attached
// and one Detached per attachment, and a client reuses an attachment slot only
// after the Detached that ends it arrives.
void XudpRelay::SendAttached(uint32_t to, uint32_t slot, uint32_t generation) noexcept {
    (void)endpoint_.TryPost(to, XudpRelayMessage{
        .kind = XudpRelayKind::Attached, .slot = slot,
        .generation = generation, .token = 0, .payload = nullptr}, SIZE_MAX);
}

void XudpRelay::SendReply(uint32_t to, uint32_t slot, uint32_t generation,
                          common::MultiBuffer datagram) noexcept {
    if (datagram.empty()) return;
    (void)endpoint_.TryPost(to, XudpRelayMessage{
        .kind = XudpRelayKind::Reply, .slot = slot, .generation = generation,
        .token = 0, .payload = datagram.pop_front().release()}, kMaxRelayBacklog);
}

void XudpRelay::SendDetached(uint32_t to, uint32_t slot, uint32_t generation) noexcept {
    (void)endpoint_.TryPost(to, XudpRelayMessage{
        .kind = XudpRelayKind::Detached, .slot = slot,
        .generation = generation, .token = 0, .payload = nullptr}, SIZE_MAX);
}

XudpRelay::Attachment XudpRelay::Open(uint32_t owner, uint64_t token, XudpClient& client) {
    uint32_t index;
    if (!free_slots_.empty()) {
        index = free_slots_.back();
        free_slots_.pop_back();
    } else if (slots_.size() < kMaxClientSlots) {
        index = static_cast<uint32_t>(slots_.size());
        slots_.emplace_back();
    } else {
        throw IoSystemError(io_error::no_buffer_space, "XUDP attachment slots exhausted");
    }
    auto& slot = slots_[index];
    const uint32_t generation = slot.generation + 1;
    slot = ClientSlot{};
    slot.generation = generation;
    slot.busy = true;
    slot.client = &client;
    try {
        endpoint_.Post(owner, XudpRelayMessage{
            .kind = XudpRelayKind::Attach, .slot = index,
            .generation = generation, .token = token, .payload = nullptr});
    } catch (...) {
        slot.busy = false;
        slot.client = nullptr;
        free_slots_.push_back(index);
        throw;
    }
    return Attachment{owner, index, generation};
}

net::awaitable<bool> XudpRelay::AwaitAttached(
    const Attachment& attachment, common::CancellationSource& cancellation) {
    common::SignalChannel wake(endpoint_.Context().get_executor(), 1);
    auto* slot = SlotFor(attachment.slot, attachment.generation);
    if (!slot) co_return false;
    slot->wake = &wake;
    struct Leave {
        XudpRelay& relay;
        const Attachment& attachment;
        ~Leave() {
            if (auto* slot = relay.SlotFor(attachment.slot, attachment.generation)) {
                slot->wake = nullptr;
            }
        }
    } leave{*this, attachment};
    ChannelWait watch(wake);
    watch.Resubscribe(cancellation);
    for (;;) {
        slot = SlotFor(attachment.slot, attachment.generation);
        if (!slot || slot->detached) co_return false;
        if (slot->attached) co_return true;
        if (watch.cancelled) co_return false;
        auto [error] = co_await wake.async_receive(net::as_tuple(net::use_awaitable));
        (void)error;
        if ((co_await net::this_coro::cancellation_state).cancelled() !=
            net::cancellation_type::none) {
            co_return false;
        }
    }
}

void XudpRelay::SendUplink(const Attachment& attachment, common::MultiBuffer datagram) noexcept {
    const auto* slot = SlotFor(attachment.slot, attachment.generation);
    if (!slot || slot->detached || datagram.empty()) return;
    (void)endpoint_.TryPost(attachment.owner, XudpRelayMessage{
        .kind = XudpRelayKind::Uplink, .slot = attachment.slot,
        .generation = attachment.generation, .token = 0,
        .payload = datagram.pop_front().release()}, kMaxRelayBacklog);
}

// The slot stays reserved until the flow Worker's Detached ends the
// attachment, so open/close churn toward a Worker that does not drain is
// bounded by the slots rather than by its rate.
void XudpRelay::Close(const Attachment& attachment) noexcept {
    auto* slot = SlotFor(attachment.slot, attachment.generation);
    if (!slot) return;
    slot->client = nullptr;
    slot->wake = nullptr;
    if (slot->detached) {
        FreeSlot(attachment.slot);
        return;
    }
    slot->closed = true;
    (void)endpoint_.TryPost(attachment.owner, XudpRelayMessage{
        .kind = XudpRelayKind::Detach, .slot = attachment.slot,
        .generation = attachment.generation, .token = 0, .payload = nullptr}, SIZE_MAX);
}

void XudpRelay::FreeSlot(uint32_t index) noexcept {
    auto& slot = slots_[index];
    slot.busy = false;
    slot.closed = false;
    slot.client = nullptr;
    slot.wake = nullptr;
    try {
        free_slots_.push_back(index);
    } catch (...) {
        // The slot stays unused; its generation still guards stale messages.
    }
}

XudpRelay::ClientSlot* XudpRelay::SlotFor(uint32_t slot, uint32_t generation) noexcept {
    if (slot >= slots_.size()) return nullptr;
    auto& entry = slots_[slot];
    return entry.busy && entry.generation == generation ? &entry : nullptr;
}

// Every attachment draws exactly one Detached from here: on refusal, when the
// flow lets it go, or acknowledging the client's Detach.
void XudpRelay::ReceiveAttach(uint32_t from, const XudpRelayMessage& message) noexcept {
    const auto found = tokens_.find(message.token);
    if (found == tokens_.end() || found->second->Closed()) {
        SendDetached(from, message.slot, message.generation);
        return;
    }
    try {
        found->second->AttachRemote(from, message.slot, message.generation);
    } catch (...) {
        found->second->DetachRemote(from, message.slot, message.generation);
        SendDetached(from, message.slot, message.generation);
    }
}

void XudpRelay::Receive(size_t from, XudpRelayMessage& message) noexcept {
    const auto source = static_cast<uint32_t>(from);
    try {
        switch (message.kind) {
        case XudpRelayKind::Attach:
            ReceiveAttach(source, message);
            return;
        case XudpRelayKind::Uplink: {
            const auto found = attachments_.find(
                AttachmentKey{source, message.slot, message.generation});
            if (found == attachments_.end()) return;
            found->second->PushUplink(common::MultiBuffer{
                common::BufferGuard{std::exchange(message.payload, nullptr)}});
            return;
        }
        case XudpRelayKind::Detach: {
            const auto found = attachments_.find(
                AttachmentKey{source, message.slot, message.generation});
            // Unbound: its Detached was already sent when the flow let it go.
            if (found == attachments_.end()) return;
            found->second->DetachRemote(source, message.slot, message.generation);
            SendDetached(source, message.slot, message.generation);
            return;
        }
        case XudpRelayKind::Attached: {
            auto* slot = SlotFor(message.slot, message.generation);
            if (!slot) return;
            slot->attached = true;
            if (slot->wake) (void)slot->wake->try_send(IoErrorCode{});
            return;
        }
        case XudpRelayKind::Reply: {
            auto* slot = SlotFor(message.slot, message.generation);
            if (!slot || slot->detached || !slot->client) return;
            (void)slot->client->PushReply(common::MultiBuffer{
                common::BufferGuard{std::exchange(message.payload, nullptr)}});
            return;
        }
        case XudpRelayKind::Detached: {
            auto* slot = SlotFor(message.slot, message.generation);
            if (!slot) return;
            if (slot->closed) {
                FreeSlot(message.slot);
                return;
            }
            if (slot->detached) return;
            slot->detached = true;
            if (slot->wake) (void)slot->wake->try_send(IoErrorCode{});
            // Taken over or ended: the sub-session ends. A refused one is
            // still waiting for its acknowledgement and claims anew.
            if (slot->attached && slot->client) slot->client->Release();
            return;
        }
        }
    } catch (...) {
        // Allocation failure drops the message like a lost datagram.
    }
}

// ---------------------------------------------------------------------------
// Sub-session side

namespace {

// Carries uplink datagrams of the sub-session into `flow` on this Worker
// until the sub-session ends or the flow leaves it.
net::awaitable<void> CarryLocal(std::shared_ptr<XudpSession> flow, XudpClient& client,
                                transport::MultiBufferReader& uplink) {
    flow->AttachLocal(client);
    try {
        for (;;) {
            auto datagram = co_await uplink.ReadMultiBuffer();
            if (datagram.empty()) break;
            if (!flow->UplinkReady(datagram, uplink.Cancellation()) &&
                !co_await flow->AwaitUplinkRoom(datagram, uplink.Cancellation())) break;
            flow->PushUplink(std::move(datagram));
        }
    } catch (...) {
        // Cancelled: the flow moved on or the Mux connection ended.
    }
    flow->DetachLocal(client);
}

// Same toward a flow of another Worker. False when that Worker refused the
// attachment: its flow ended before the attachment reached it.
net::awaitable<bool> CarryRemote(XudpRelay& relay, uint32_t owner, uint64_t token,
                                 XudpClient& client, transport::MultiBufferReader& uplink) {
    const auto attachment = relay.Open(owner, token, client);
    struct CloseAttachment {
        XudpRelay& relay;
        const XudpRelay::Attachment& attachment;
        ~CloseAttachment() { relay.Close(attachment); }
    } close{relay, attachment};
    if (!co_await relay.AwaitAttached(attachment, uplink.Cancellation())) {
        co_return uplink.Cancellation().Stopped();
    }
    try {
        for (;;) {
            auto datagram = co_await uplink.ReadMultiBuffer();
            if (datagram.empty()) break;
            relay.SendUplink(attachment, std::move(datagram));
        }
    } catch (...) {
        // Cancelled: the flow moved on or the Mux connection ended.
    }
    co_return true;
}

}  // namespace

net::awaitable<bool> RunXudpSubSession(
    const XudpDispatchEnvironment& environment, common::Context& sub_ctx,
    XudpGlobalId global_id, XudpClient& client, transport::MultiBufferReader& uplink) {
    auto& table = net::use_service<XudpSessionTable>(environment.io_context);
    auto* relay = common::FindWorkerMesh<XudpRelay>(environment.io_context);
    const auto key = MakeXudpKey(sub_ctx, global_id);
    // A claim lost to a flow that ends at once is retried; a flow keeps
    // ending under it only on a misbehaving client.
    for (int attempt = 0; attempt < 3; ++attempt) {
        if (table.Stopping()) co_return false;
        if (auto flow = table.Find(key); flow && !flow->Closed()) {
            co_await CarryLocal(std::move(flow), client, uplink);
            co_return true;
        }
        if (table.Full()) co_return false;
        auto flow = std::make_shared<XudpSession>(environment, sub_ctx, key, relay, table);
        if (relay) {
            // Bound before the directory can announce it: an attachment from
            // another Worker may arrive before the claim returns here.
            flow->token = relay->ReserveToken(*flow);
            auto claim = co_await app::ClaimSessionOwner(
                environment.admission.coordinator, key,
                app::SessionOwner{relay->Index(), flow->token});
            if (claim.owner.worker != relay->Index() || claim.owner.token != flow->token) {
                // Never announced: nothing attached to this candidate.
                relay->ReleaseToken(std::exchange(flow->token, 0));
                flow.reset();
                if (claim.owner.worker == relay->Index()) continue;
                if (uplink.Cancellation().Stopped()) co_return true;
                if (co_await CarryRemote(*relay, claim.owner.worker, claim.owner.token,
                                         client, uplink)) {
                    co_return true;
                }
                continue;
            }
            flow->ownership = std::move(claim.ownership);
            if (table.Stopping()) {
                flow->Close();
                co_return false;
            }
        }
        table.Insert(key, flow);
        try {
            flow->Start();
        } catch (...) {
            flow->Close();
            throw;
        }
        co_await CarryLocal(std::move(flow), client, uplink);
        co_return true;
    }
    co_return false;
}

void StopXudpSessions(net::io_context& io_context) noexcept {
    if (net::has_service<XudpSessionTable>(io_context)) {
        net::use_service<XudpSessionTable>(io_context).RequestStop();
    }
}

net::awaitable<void> JoinXudpSessions(net::io_context& io_context) {
    if (net::has_service<XudpSessionTable>(io_context)) {
        co_await net::use_service<XudpSessionTable>(io_context).Join();
    }
}

}  // namespace proxy
