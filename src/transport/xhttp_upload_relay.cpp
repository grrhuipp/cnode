#include "transport/xhttp_upload_relay.hpp"

#include "common/allocator.hpp"
#include "common/error.hpp"
#include "transport/xhttp_session.hpp"

#include <asio/as_tuple.hpp>
#include <asio/this_coro.hpp>

#include <algorithm>
#include <deque>
#include <unordered_map>
#include <utility>
#include <vector>

namespace transport {
namespace {

using RelayKind = XHttpRelayKind;
using RelayMessage = XHttpRelayMessage;

// Packet bytes one Worker may have read toward one other Worker that its
// session has not yet taken; bounded like a session's own payload budget.
constexpr size_t kPacketBudget = 4 * XHttpPacketQueue::kMaxQueuedBytes;
// Stream-up bytes in flight or unread per remote upload: the receiver window.
constexpr int64_t kStreamWindow = 1024 * 1024;
// Stream bytes consumed before the session Worker returns them as credit.
constexpr size_t kCreditBatch = 64 * 1024;
// Concurrent uploads from one Worker toward one other Worker.
constexpr size_t kMaxUploadSlots = 64 * 1024;

void FreePayload(RelayMessage& message) noexcept {
    ReleaseWorkerMessage(message);
}

uint64_t StreamKey(uint32_t slot, uint32_t generation) noexcept {
    return (static_cast<uint64_t>(slot) << 32) | generation;
}

}  // namespace
class XHttpRemoteUploadStream;

struct XHttpUploadRelay::State {
    struct UploadSlot {
        uint32_t generation = 0;
        bool busy = false;
        // Packet: the session answered. Stream: the session ended the upload.
        bool finished = false;
        // Packet: its waiter left before the answer.
        bool abandoned = false;
        // Stream: the pump sent its last message.
        bool sending_done = false;
        XHttpCommit commit = XHttpCommit::Missing;
        size_t reserved = 0;
        int64_t credit = 0;
        // Frame-local channel of the coroutine waiting on this slot.
        common::SignalChannel* wake = nullptr;
        // Stream: its body, whose read is cancelled when the session ends.
        AsyncStream* upload = nullptr;
    };

    struct Link {
        // Upload side toward this peer. A deque keeps slot addresses stable.
        std::deque<UploadSlot> slots;
        std::vector<uint32_t> free_slots;
        size_t packet_bytes = 0;
        std::vector<common::SignalChannel*> budget_waiters;
        // Session side: stream uploads arriving from this peer.
        std::unordered_map<uint64_t, XHttpRemoteUploadStream*> streams;
        // Session side: streams whose open waits for its session token to
        // bind; their later messages wait behind it, in order.
        std::unordered_map<uint64_t, uint64_t> parked_streams;
    };

    struct SessionEntry {
        // Null while the token is reserved but its session not yet bound.
        XHttpPacketUpSession* session = nullptr;
        common::RingDeque<std::pair<size_t, RelayMessage>> parked;
    };

    using Endpoint = common::WorkerMeshEndpoint<State, RelayMessage, 256>;

    State(net::io_context& io, std::shared_ptr<Mesh> mesh, size_t index)
        : io(io), links(mesh->Size()), endpoint(*this, io, std::move(mesh), index) {}

    void Receive(size_t from, RelayMessage& message) noexcept {
        try {
            Dispatch(from, message);
        } catch (...) {
            // Allocation failure: the message is dropped like one toward a
            // stopped Worker; its waiter keeps waiting until cancelled.
        }
    }

    void Post(size_t to, RelayMessage message) { endpoint.Post(to, message); }

    // Takes the message into `parked`; the caller's copy no longer owns it.
    static void Park(common::RingDeque<std::pair<size_t, RelayMessage>>& parked,
                     size_t from, RelayMessage& message) {
        parked.push_back({from, message});
        message.payload = nullptr;
    }

    void Dispatch(size_t from, RelayMessage& message);
    void OnPacket(size_t from, RelayMessage& message);
    void OnStreamOpen(size_t from, RelayMessage& message);
    void OnUploadReply(size_t from, const RelayMessage& message) noexcept;

    // Null session and false: unknown token. Null session and true: parked.
    [[nodiscard]] std::pair<XHttpPacketUpSession*, bool> SessionFor(
        size_t from, RelayMessage& message) {
        const auto found = sessions.find(message.session);
        if (found == sessions.end()) return {nullptr, false};
        if (!found->second.session) {
            Park(found->second.parked, from, message);
            return {nullptr, true};
        }
        return {found->second.session, false};
    }

    [[nodiscard]] std::optional<uint32_t> AllocateSlot(Link& link) {
        uint32_t index_in_link;
        if (!link.free_slots.empty()) {
            index_in_link = link.free_slots.back();
            link.free_slots.pop_back();
        } else if (link.slots.size() < kMaxUploadSlots) {
            index_in_link = static_cast<uint32_t>(link.slots.size());
            link.slots.emplace_back();
        } else {
            return std::nullopt;
        }
        auto& slot = link.slots[index_in_link];
        const uint32_t generation = slot.generation + 1;
        slot = UploadSlot{};
        slot.generation = generation;
        slot.busy = true;
        return index_in_link;
    }

    void FreeSlot(Link& link, uint32_t index_in_link) {
        link.slots[index_in_link].busy = false;
        link.free_slots.push_back(index_in_link);
    }

    [[nodiscard]] UploadSlot* SlotFor(Link& link, const RelayMessage& message) noexcept {
        if (message.slot >= link.slots.size()) return nullptr;
        auto& slot = link.slots[message.slot];
        return slot.busy && slot.generation == message.generation ? &slot : nullptr;
    }

    static void Wake(UploadSlot& slot) noexcept {
        if (slot.wake) (void)slot.wake->try_send(IoErrorCode{});
    }

    void ReleasePacketBytes(size_t owner, size_t bytes) noexcept {
        auto& link = links[owner];
        link.packet_bytes -= std::min(link.packet_bytes, bytes);
        for (auto* waiter : link.budget_waiters) (void)waiter->try_send(IoErrorCode{});
    }

    net::io_context& io;
    std::vector<Link> links;
    std::unordered_map<uint64_t, SessionEntry> sessions;
    uint64_t next_token = 0;
    // Last: destroyed first, before the state its receiver touches.
    Endpoint endpoint;
};

// Session-side end of one stream-up upload received on another Worker. The
// session reads it like a local upload; bytes it consumes return to the
// upload Worker as credit.
class XHttpRemoteUploadStream final : public AsyncStream {
public:
    XHttpRemoteUploadStream(XHttpUploadRelay::State& relay, size_t from,
                            uint32_t slot, uint32_t generation)
        : relay_(&relay), from_(from), slot_(slot), generation_(generation)
        , signal_(relay.io.get_executor(), 1) {
        relay.links[from].streams.emplace(StreamKey(slot, generation), this);
    }

    ~XHttpRemoteUploadStream() noexcept override { Finish(); }

    void Deliver(common::MultiBuffer payload) {
        if (finished_) return;
        inbox_bytes_ += payload.byte_size();
        if (inbox_bytes_ > static_cast<size_t>(kStreamWindow) + common::Buffer::kSize * 64) {
            // The upload Worker ignored its window.
            aborted_ = true;
            inbox_.clear();
        } else {
            inbox_.push_back(std::move(payload));
        }
        Wake();
    }
    void DeliverEnd() noexcept { ended_ = true; Wake(); }
    void DeliverAbort() noexcept { aborted_ = true; Wake(); }
    // The relay is shutting down; this stream can no longer report back.
    void Detach() noexcept { relay_ = nullptr; finished_ = true; }

    net::awaitable<size_t> AsyncRead(net::mutable_buffer buffer) override {
        if (buffer.size() == 0) co_return 0;
        for (;;) {
            if (!inbox_.empty()) {
                auto& front = inbox_.front();
                const size_t n = front.ConsumePrefixTo(
                    std::span<uint8_t>(static_cast<uint8_t*>(buffer.data()), buffer.size()));
                if (front.empty()) inbox_.pop_front();
                Consumed(n);
                co_return n;
            }
            if (co_await WaitInput()) co_return 0;
        }
    }

    net::awaitable<common::MultiBuffer> ReadMultiBuffer() override {
        for (;;) {
            if (!inbox_.empty()) {
                auto payload = std::move(inbox_.front());
                inbox_.pop_front();
                Consumed(payload.byte_size());
                co_return payload;
            }
            if (co_await WaitInput()) co_return common::MultiBuffer{};
        }
    }

    net::awaitable<void> WriteBuffers(std::span<const net::const_buffer>) override {
        throw IoSystemError(io_error::operation_not_supported, "xhttp upload stream is read-only");
    }
    void ShutdownWrite() override {}
    void Cancel() noexcept override {
        ++read_abort_epoch_;
        Wake();
    }
    void Close() override {
        if (closed_) return;
        closed_ = true;
        Finish();
        NotifyClosed();
        Wake();
    }
    void CloseAbortive() override { Close(); }
    int NativeHandle() const override { return -1; }
    bool IsOpen() const override { return !closed_; }

private:
    // True at EOF; throws when the upload was aborted or this read cancelled.
    net::awaitable<bool> WaitInput() {
        for (;;) {
            if (!inbox_.empty()) co_return false;
            if (aborted_) throw IoSystemError(io_error::connection_reset, "xhttp upload aborted");
            if (ended_ || closed_ || finished_) co_return true;
            const uint64_t epoch = read_abort_epoch_;
            auto [error] = co_await signal_.async_receive(net::as_tuple(net::use_awaitable));
            if (error || epoch != read_abort_epoch_) {
                throw IoSystemError(io_error::operation_aborted, "xhttp upload read cancelled");
            }
        }
    }

    void Wake() noexcept { (void)signal_.try_send(IoErrorCode{}); }

    void Consumed(size_t bytes) {
        inbox_bytes_ -= std::min(inbox_bytes_, bytes);
        pending_credit_ += bytes;
        if (!relay_ || finished_ || ended_) return;
        if (pending_credit_ < kCreditBatch && !inbox_.empty()) return;
        relay_->Post(from_, RelayMessage{
            .kind = RelayKind::StreamCredit, .slot = slot_, .generation = generation_,
            .value = std::exchange(pending_credit_, 0)});
    }

    // Reports the end of this upload to the upload Worker exactly once.
    void Finish() noexcept {
        if (finished_) return;
        finished_ = true;
        inbox_.clear();
        if (!relay_) return;
        relay_->links[from_].streams.erase(StreamKey(slot_, generation_));
        try {
            relay_->Post(from_, RelayMessage{
                .kind = RelayKind::StreamClosed, .slot = slot_, .generation = generation_});
        } catch (...) {
            // Allocation failure: the upload Worker keeps the slot until shutdown.
        }
    }

    XHttpUploadRelay::State* relay_;
    size_t from_;
    uint32_t slot_;
    uint32_t generation_;
    common::SignalChannel signal_;
    common::RingDeque<common::MultiBuffer> inbox_;
    size_t inbox_bytes_ = 0;
    size_t pending_credit_ = 0;
    uint64_t read_abort_epoch_ = 0;
    bool ended_ = false;
    bool aborted_ = false;
    bool closed_ = false;
    bool finished_ = false;
};

void XHttpUploadRelay::State::Dispatch(size_t from, RelayMessage& message) {
    switch (message.kind) {
    case RelayKind::Packet:
        OnPacket(from, message);
        return;
    case RelayKind::StreamOpen:
        OnStreamOpen(from, message);
        return;
    case RelayKind::StreamData:
    case RelayKind::StreamEnd:
    case RelayKind::StreamAbort: {
        const uint64_t key = StreamKey(message.slot, message.generation);
        auto& link = links[from];
        if (const auto parked = link.parked_streams.find(key); parked != link.parked_streams.end()) {
            const auto entry = sessions.find(parked->second);
            if (entry != sessions.end() && !entry->second.session) {
                Park(entry->second.parked, from, message);
                return;
            }
            link.parked_streams.erase(parked);
        }
        const auto found = link.streams.find(key);
        if (found == link.streams.end()) {
            FreePayload(message);
            return;
        }
        if (message.kind == RelayKind::StreamData) {
            found->second->Deliver(common::MultiBuffer{
                common::BufferGuard{std::exchange(message.payload, nullptr)}});
        } else if (message.kind == RelayKind::StreamEnd) {
            found->second->DeliverEnd();
        } else {
            found->second->DeliverAbort();
        }
        return;
    }
    case RelayKind::PacketDone:
    case RelayKind::StreamCredit:
    case RelayKind::StreamClosed:
        OnUploadReply(from, message);
        return;
    }
    FreePayload(message);
}

void XHttpUploadRelay::State::OnPacket(size_t from, RelayMessage& message) {
    const auto [session, parked] = SessionFor(from, message);
    if (parked) return;
    common::MultiBuffer payload{common::BufferGuard{std::exchange(message.payload, nullptr)}};
    XHttpCommit commit = XHttpCommit::Missing;
    if (session) {
        try {
            commit = session->Push(message.value, std::move(payload))
                ? XHttpCommit::Committed : XHttpCommit::Rejected;
        } catch (...) {
            commit = XHttpCommit::Rejected;
        }
    }
    Post(from, RelayMessage{
        .kind = RelayKind::PacketDone, .commit = commit,
        .slot = message.slot, .generation = message.generation});
}

void XHttpUploadRelay::State::OnStreamOpen(size_t from, RelayMessage& message) {
    const uint64_t key = StreamKey(message.slot, message.generation);
    links[from].parked_streams.erase(key);
    const auto [session, parked] = SessionFor(from, message);
    if (parked) {
        links[from].parked_streams.emplace(key, message.session);
        return;
    }
    if (!session || !session->CanAttachStream()) {
        Post(from, RelayMessage{
            .kind = RelayKind::StreamClosed, .slot = message.slot, .generation = message.generation});
        return;
    }
    // A refused stream reports StreamClosed from its destructor.
    (void)session->AttachStream(std::make_unique<XHttpRemoteUploadStream>(
        *this, from, message.slot, message.generation));
}

void XHttpUploadRelay::State::OnUploadReply(size_t from, const RelayMessage& message) noexcept {
    auto& link = links[from];
    auto* slot = SlotFor(link, message);
    if (!slot) return;
    switch (message.kind) {
    case RelayKind::PacketDone:
        ReleasePacketBytes(from, std::exchange(slot->reserved, 0));
        slot->finished = true;
        slot->commit = message.commit;
        if (slot->abandoned) {
            FreeSlot(link, message.slot);
        } else {
            Wake(*slot);
        }
        return;
    case RelayKind::StreamCredit:
        slot->credit += static_cast<int64_t>(message.value);
        Wake(*slot);
        return;
    case RelayKind::StreamClosed:
        slot->finished = true;
        if (slot->upload) slot->upload->Cancel();
        Wake(*slot);
        if (slot->sending_done) FreeSlot(link, message.slot);
        return;
    default:
        return;
    }
}

namespace {

// Waits until the slot changes or the upload's connection is cancelled.
// Returns true when cancelled, by the connection or by this coroutine.
struct SlotWait final : common::CancellationSubscription {
    explicit SlotWait(common::SignalChannel& wake) noexcept : wake(wake) {}
    common::SignalChannel& wake;
    bool cancelled = false;

private:
    void OnCancellation(common::Cancellation) noexcept override {
        cancelled = true;
        (void)wake.try_send(IoErrorCode{});
    }
};

net::awaitable<bool> WaitOnce(common::SignalChannel& wake, SlotWait& watch,
                              common::CancellationSource& cancellation) {
    if (!watch.cancelled) watch.Resubscribe(cancellation);
    if (watch.cancelled) co_return true;
    auto [error] = co_await wake.async_receive(net::as_tuple(net::use_awaitable));
    (void)error;
    if ((co_await net::this_coro::cancellation_state).cancelled() != net::cancellation_type::none) {
        co_return true;
    }
    co_return watch.cancelled;
}

}  // namespace

XHttpUploadRelay::XHttpUploadRelay(net::io_context& io_context,
                                   std::shared_ptr<Mesh> mesh, size_t index)
    : state_(std::make_unique<State>(io_context, std::move(mesh), index)) {}

XHttpUploadRelay::~XHttpUploadRelay() = default;

void XHttpUploadRelay::Stop() noexcept { state_->endpoint.Stop(); }

void XHttpUploadRelay::Shutdown() noexcept {
    auto& state = *state_;
    state.endpoint.Shutdown();
    for (auto& link : state.links) {
        for (auto& [key, stream] : link.streams) {
            (void)key;
            stream->Detach();
        }
        link.streams.clear();
    }
    for (auto& [token, entry] : state.sessions) {
        (void)token;
        if (entry.session) entry.session->DetachRelay();
        while (!entry.parked.empty()) {
            FreePayload(entry.parked.front().second);
            entry.parked.pop_front();
        }
    }
    state.sessions.clear();
}

std::optional<size_t> XHttpUploadRelay::EndpointOf(const net::io_context& owner) const noexcept {
    return state_->endpoint.IndexOf(owner);
}

uint64_t XHttpUploadRelay::ReserveSessionToken() {
    const uint64_t token = ++state_->next_token;
    state_->sessions.try_emplace(token);
    return token;
}

void XHttpUploadRelay::BindSession(uint64_t token, XHttpPacketUpSession& session) {
    const auto found = state_->sessions.find(token);
    if (found == state_->sessions.end()) return;
    found->second.session = &session;
    session.AttachRelay(*this, token);
    auto parked = std::move(found->second.parked);
    while (!parked.empty()) {
        auto [from, message] = parked.front();
        parked.pop_front();
        state_->Receive(from, message);
        FreePayload(message);
    }
}

void XHttpUploadRelay::ReleaseSessionToken(uint64_t token) noexcept {
    auto& state = *state_;
    const auto found = state.sessions.find(token);
    if (found == state.sessions.end()) return;
    auto parked = std::move(found->second.parked);
    state.sessions.erase(found);
    // Parked messages now find no session: packets answer Missing and
    // streams report closed.
    while (!parked.empty()) {
        auto [from, message] = parked.front();
        parked.pop_front();
        state.Receive(from, message);
        FreePayload(message);
    }
}

bool XHttpUploadRelay::TryReservePacketBytes(size_t owner, size_t bytes) noexcept {
    auto& link = state_->links[owner];
    if (bytes > kPacketBudget - link.packet_bytes) return false;
    link.packet_bytes += bytes;
    return true;
}

void XHttpUploadRelay::ReleasePacketBytes(size_t owner, size_t bytes) noexcept {
    state_->ReleasePacketBytes(owner, bytes);
}

net::awaitable<bool> XHttpUploadRelay::AwaitPacketBudget(
    size_t owner, common::CancellationSource& cancellation) {
    auto& link = state_->links[owner];
    common::SignalChannel wake(state_->io.get_executor(), 1);
    link.budget_waiters.push_back(&wake);
    struct Unregister {
        std::vector<common::SignalChannel*>& waiters;
        common::SignalChannel* wake;
        ~Unregister() { std::erase(waiters, wake); }
    } unregister{link.budget_waiters, &wake};
    SlotWait watch(wake);
    co_return !co_await WaitOnce(wake, watch, cancellation);
}

net::awaitable<XHttpCommit> XHttpUploadRelay::SendPacket(
    size_t owner, uint64_t token, uint64_t seq, common::MultiBuffer payload,
    size_t reserved, common::CancellationSource& cancellation) {
    auto& state = *state_;
    auto& link = state.links[owner];
    const auto index_in_link = state.AllocateSlot(link);
    if (!index_in_link) {
        state.ReleasePacketBytes(owner, reserved);
        co_return XHttpCommit::Rejected;
    }
    auto& slot = link.slots[*index_in_link];
    slot.reserved = reserved;
    common::SignalChannel wake(state.io.get_executor(), 1);
    slot.wake = &wake;
    struct Leave {
        State::UploadSlot& slot;
        ~Leave() {
            slot.wake = nullptr;
            if (!slot.finished) slot.abandoned = true;
        }
    } leave{slot};
    try {
        state.Post(owner, RelayMessage{
            .kind = RelayKind::Packet, .slot = *index_in_link, .generation = slot.generation,
            .session = token, .value = seq, .payload = payload.pop_front().release()});
    } catch (...) {
        // Never sent: no answer will free the slot or the budget.
        state.ReleasePacketBytes(owner, std::exchange(slot.reserved, 0));
        slot.finished = true;
        state.FreeSlot(link, *index_in_link);
        throw;
    }
    SlotWait watch(wake);
    while (!slot.finished) {
        if (co_await WaitOnce(wake, watch, cancellation)) co_return XHttpCommit::Missing;
    }
    const XHttpCommit commit = slot.commit;
    slot.wake = nullptr;
    state.FreeSlot(link, *index_in_link);
    co_return commit;
}

net::awaitable<void> XHttpUploadRelay::PumpStream(
    size_t owner, uint64_t token, AsyncStream& upload) {
    auto& state = *state_;
    auto& link = state.links[owner];
    const auto index_in_link = state.AllocateSlot(link);
    if (!index_in_link) {
        throw IoSystemError(io_error::no_buffer_space, "xhttp upload relay slots exhausted");
    }
    auto& slot = link.slots[*index_in_link];
    const uint32_t generation = slot.generation;
    slot.credit = kStreamWindow;
    slot.upload = &upload;
    common::SignalChannel wake(state.io.get_executor(), 1);
    slot.wake = &wake;
    struct Leave {
        State& state;
        State::Link& link;
        uint32_t index_in_link;
        ~Leave() {
            auto& slot = link.slots[index_in_link];
            slot.wake = nullptr;
            slot.upload = nullptr;
            slot.sending_done = true;
            if (slot.finished) state.FreeSlot(link, index_in_link);
        }
    } leave{state, link, *index_in_link};
    const auto send = [&](RelayKind kind, common::Buffer* payload = nullptr) {
        state.Post(owner, RelayMessage{
            .kind = kind, .slot = *index_in_link, .generation = generation,
            .session = token, .payload = payload});
    };
    try {
        send(RelayKind::StreamOpen);
    } catch (...) {
        // Never opened: no StreamClosed will come.
        slot.finished = true;
        throw;
    }
    SlotWait watch(wake);
    try {
        for (;;) {
            while (slot.credit <= 0 && !slot.finished) {
                if (co_await WaitOnce(wake, watch, upload.Cancellation())) {
                    throw IoSystemError(io_error::operation_aborted, "xhttp upload cancelled");
                }
            }
            if (slot.finished) co_return;
            auto payload = co_await upload.ReadMultiBuffer();
            if (slot.finished) co_return;
            if (payload.byte_size() == 0) {
                send(RelayKind::StreamEnd);
                co_return;
            }
            slot.credit -= static_cast<int64_t>(payload.byte_size());
            send(RelayKind::StreamData, payload.pop_front().release());
        }
    } catch (...) {
        // The session ending the upload cancels the read; that is its end.
        if (slot.finished) co_return;
        send(RelayKind::StreamAbort);
        throw;
    }
}

}  // namespace transport
