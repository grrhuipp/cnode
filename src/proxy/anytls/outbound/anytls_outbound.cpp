#include "common/address_codec.hpp"
#include "common/awaitable_task_group.hpp"

#include "proxy/anytls/anytls_codec.hpp"
#include "proxy/anytls_padding.hpp"
#include "common/buf/length_prefixed_packet_buffer.hpp"
#include "proxy/outbound_stream_endpoint.hpp"
#include "proxy/handshake_errors.hpp"
#include "proxy/uot/uot.hpp"
#include "transport/internet/async_write_gate.hpp"
#include "app/dns/dns.hpp"
#include "app/relay.hpp"
#include "app/stats.hpp"
#include "common/ip_utils.hpp"
#include "common/hash_container_shrink.hpp"
#include "common/session.hpp"
#include "infra/log.hpp"
#include "common/error.hpp"
#include "infra/config_types.hpp"
#include "app/proxyman/outbound/handler.hpp"
#include "transport/internet/outbound_target_builder.hpp"
#include "transport/internet/timeout_scheduler.hpp"
#include "transport/failure.hpp"
#include "common/scoped_cleanse.hpp"

#include <asio/experimental/channel.hpp>
#include <algorithm>
#include <chrono>
#include <exception>
#include <limits>
#include <format>
#include <stdexcept>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>
#include <unordered_map>

namespace {

constexpr size_t kMaxLogicalQueuedPayloadBytes = ::proxy::anytls::kMaxFramePayload;
// anytls-go Session.OpenStream: a v2 stream with sid >= 2 must see SYNACK
// within 3 s or the whole session closes (proxy/session/session.go).
constexpr std::chrono::seconds kSynAckTimeout{3};

}  // namespace

namespace proxy::anytls::outbound {


// The cache host alone publishes and reads the next-handshake snapshot. Each
// physical reader awaits its control update (at most one outstanding per
// session); it never forwards payload or changes another session's scheme.
struct Handler::PaddingState {
    void Publish(std::shared_ptr<const PaddingScheme> next) noexcept {
        scheme = std::move(next);
    }

    std::shared_ptr<const PaddingScheme> scheme{DefaultPaddingScheme()};
};

struct Handler::ClientSession {
    class LogicalStream final {
    public:
        explicit LogicalStream(net::any_io_executor executor)
            : syn_signal_(executor, 1)
            , payload_signal_(executor, 1)
            , payload_space_signal_(std::move(executor), 1) {}

        ~LogicalStream() noexcept {
            Close(common::ErrorCode::CANCELLED);
        }

        LogicalStream(const LogicalStream&) = delete;
        LogicalStream& operator=(const LogicalStream&) = delete;

        net::awaitable<void> PushPayload(buf::MultiBuffer mb) {
            const size_t bytes = mb.byte_size();
            if (bytes == 0 || closed_) co_return;
            // The physical reader owns this payload while capacity is used
            // by the logical queue. Awaiting consumption also stops TLS reads.
            while (!closed_ && queued_payload_.byte_size() + bytes > kMaxLogicalQueuedPayloadBytes) {
                auto [ec] = co_await payload_space_signal_.async_receive(
                    net::as_tuple(net::use_awaitable));
                if (ec) co_return;
            }
            if (closed_) co_return;
            buf::AppendCoalescedStreamInput(queued_payload_, std::move(mb));
            WakePayloadReader();
        }

        transport::CancellationSource& Cancellation() noexcept { return cancellation_; }

        void CheckWrite() const {
            if (error_ != common::ErrorCode::OK) throw transport::LinkError(error_);
            if (closed_) throw transport::WriteClosed();
        }

        void CloseRemote() noexcept {
            remote_closed_ = true;
            Close();
        }

        bool BeginLocalClose() noexcept {
            if (closed_) return false;
            queued_payload_.clear();
            Close();
            return true;
        }

        bool RemoteClosed() const noexcept { return remote_closed_; }

        void Close(common::ErrorCode error = common::ErrorCode::OK) noexcept {
            if (closed_ && (error_ != common::ErrorCode::OK || error == common::ErrorCode::OK)) return;
            // Publish the terminal state before cancellation can re-enter us.
            // An error after FIN discards unread bytes; the first error wins.
            closed_ = true;
            error_ = error;
            if (error != common::ErrorCode::OK) {
                queued_payload_.clear();
                cancellation_.Stop(error);
            }
            WakeOpenWaiter();
            WakePayloadReader();
            WakePayloadWriter();
        }

        void AckSyn() noexcept {
            syn_acked_ = true;
            WakeOpenWaiter();
        }

        net::awaitable<tl::expected<void, common::ErrorCode>> WaitOpenResult(
            std::chrono::seconds timeout, net::io_context& io_context) {
            auto result = OpenResult();
            if (!result) {
                // The finite wait owns its deadline. ACK, FIN and errors are
                // persistent state; a channel notification is only a wakeup.
                struct OpenDeadline final : transport::internet::TimeoutEvent {
                    OpenDeadline(LogicalStream& owner, net::io_context& io) noexcept
                        : TimeoutEvent(io), owner(owner) {}
                    void OnTimeout() override {
                        if (!owner.OpenResult()) owner.Close(common::ErrorCode::TIMEOUT);
                    }
                    LogicalStream& owner;
                } deadline(*this, io_context);
                if (!deadline.ScheduleAfter(
                        std::chrono::duration_cast<std::chrono::milliseconds>(timeout)))
                    co_return tl::unexpected(common::ErrorCode::CANCELLED);
                do {
                    const auto [ec] = co_await syn_signal_.async_receive(
                        net::as_tuple(net::use_awaitable));
                    if (ec && !OpenResult()) Close(common::ErrorCode::CANCELLED);
                    result = OpenResult();
                } while (!result);
            }
            if (*result != common::ErrorCode::OK) co_return tl::unexpected(*result);
            co_return tl::expected<void, common::ErrorCode>{};
        }

        net::awaitable<tl::expected<buf::MultiBuffer, common::ErrorCode>> ReadPayload() {
            while (queued_payload_.empty() && !closed_) {
                auto [ec] = co_await payload_signal_.async_receive(
                    net::as_tuple(net::use_awaitable));
                if (ec) {
                    co_return tl::unexpected(common::ErrorCode::CANCELLED);
                }
            }
            if (!queued_payload_.empty()) {
                auto payload = std::move(queued_payload_);
                queued_payload_.ReleaseIfIdle();
                WakePayloadWriter();
                co_return payload;
            }
            queued_payload_.ReleaseIfIdle();
            co_return tl::unexpected(error_);
        }

    private:
        void WakePayloadWriter() noexcept {
            (void)payload_space_signal_.try_send(IoErrorCode{});
        }

        std::optional<common::ErrorCode> OpenResult() const noexcept {
            if (error_ != common::ErrorCode::OK) return error_;
            // Clean FIN may precede the ACK. Relay still owns delivery of
            // queued bytes and completion of both application directions.
            if (closed_ || syn_acked_) return common::ErrorCode::OK;
            return std::nullopt;
        }

        void WakeOpenWaiter() noexcept {
            (void)syn_signal_.try_send(IoErrorCode{});
        }

        void WakePayloadReader() noexcept {
            (void)payload_signal_.try_send(IoErrorCode{});
        }

        transport::CancellationSource cancellation_;
        common::SignalChannel syn_signal_;
        common::SignalChannel payload_signal_;
        common::SignalChannel payload_space_signal_;
        buf::MultiBuffer queued_payload_;
        common::ErrorCode error_ = common::ErrorCode::OK;
        bool closed_ = false;
        bool remote_closed_ = false;
        bool syn_acked_ = false;
    };

    ClientSession(net::io_context& io_context, std::unique_ptr<transport::AsyncStream> s,
                  std::shared_ptr<PaddingState> padding_state,
                  std::shared_ptr<const PaddingScheme> opening_scheme)
        : io_context_(io_context)
        , stream(std::move(s))
        , padding_state_(std::move(padding_state))
        , opening_scheme_(std::move(opening_scheme))
        , scheme_(opening_scheme_)
        , local_endpoint(stream->LocalEndpoint())
        , remote_endpoint(stream->RemoteEndpoint()) {}

    net::io_context& io_context_;
    std::unique_ptr<transport::AsyncStream> stream;
    std::shared_ptr<PaddingState> padding_state_;
    // Authentication, first settings, and first framed write use one snapshot.
    // Releasing it also records that settings have been sent successfully.
    std::shared_ptr<const PaddingScheme> opening_scheme_;
    std::shared_ptr<const PaddingScheme> scheme_;
    const std::optional<tcp::endpoint> local_endpoint;
    const std::optional<tcp::endpoint> remote_endpoint;
    uint32_t next_sid = 1;
    bool sid_exhausted = false;
    uint32_t packet_index = 1;
    std::optional<SessionVersion> session_version;
    transport::internet::AsyncWriteGate write_gate;
    std::unordered_map<
        uint32_t,
        std::weak_ptr<LogicalStream>>
        logical_streams;
    size_t active_streams = 0;
    bool closed = false;
    // First terminal cause. The physical loop can fail inline while Adopt
    // starts it, before the request registers its logical stream; requests
    // that then find the session closed report this cause, not a generic close.
    common::ErrorCode close_error = common::ErrorCode::OK;

    [[nodiscard]] bool IsClosed() const noexcept { return closed || !stream; }

    [[nodiscard]] common::ErrorCode ClosedError() const noexcept {
        return close_error != common::ErrorCode::OK ? close_error : common::ErrorCode::CONNECTION_CLOSED;
    }

    uint32_t NextPacketIndex() noexcept {
        const auto index = packet_index;
        // Index zero belongs to authentication. Saturate before wrapping into it.
        if (packet_index != UINT32_MAX) ++packet_index;
        return index;
    }

    [[nodiscard]] bool Available() const noexcept {
        return !closed && stream && active_streams == 0 && !sid_exhausted;
    }

    uint32_t AllocateSid() noexcept {
        const uint32_t sid = next_sid;
        if (next_sid == std::numeric_limits<uint32_t>::max()) {
            sid_exhausted = true;
        } else {
            ++next_sid;
        }
        return sid;
    }

    std::shared_ptr<LogicalStream> RegisterLogicalStream(uint32_t sid) {
        auto logical = std::make_shared<LogicalStream>(
            net::any_io_executor(io_context_.get_executor()));
        logical_streams[sid] = logical;
        return logical;
    }

    void UnregisterLogicalStream(uint32_t sid) {
        logical_streams.erase(sid);
        common::MaybeShrinkHashContainer(logical_streams, 8);
    }

    void CloseAll(common::ErrorCode error) noexcept {
        if (closed) return;
        closed = true;
        close_error = error;
        write_gate.Cancel();
        auto streams = std::exchange(
            logical_streams,
            std::unordered_map<uint32_t, std::weak_ptr<LogicalStream>>{
                logical_streams.get_allocator()});
        for (auto& [sid, weak] : streams) {
            (void)sid;
            if (auto logical = weak.lock()) {
                logical->Close(error);
            }
        }
        if (stream) {
            stream->CloseAbortive();
        }
    }

    // 填充分支把方案内的记录借给跨挂起点的写协程，读循环可能同时替换 scheme_，
    // 因此只在该包有填充记录时持有快照；无填充分支在调用内同步消费方案。
    std::shared_ptr<const PaddingScheme> SchemeGuardFor(uint32_t packet_index) const noexcept {
        if (scheme_->RecordFor(packet_index).empty()) return {};
        return scheme_;
    }

    net::awaitable<tl::expected<void, common::ErrorCode>>
    WriteOpenPacket(std::vector<uint8_t> packet) {
        auto write_lease = write_gate.TryAcquire();
        if (!write_lease) write_lease = co_await write_gate.Acquire();
        if (!write_lease || closed || !stream) {
            co_return tl::unexpected(ClosedError());
        }

        try {
            auto scheme_snapshot = opening_scheme_ ? opening_scheme_ : scheme_;
            const uint32_t this_packet = NextPacketIndex();
            auto ok = co_await WritePacketWithPadding(
                *stream, *scheme_snapshot, this_packet, std::move(packet));
            if (!ok) {
                CloseAll(ok.error());
                co_return tl::unexpected(ok.error());
            }
            opening_scheme_.reset();
            co_return tl::expected<void, common::ErrorCode>{};
        } catch (...) {
            // 未知异常按写失败归类：物理写失败不能以读失败形态到达 relay。
            CloseAll(transport::ClassifyFailure(std::current_exception(), common::ErrorCode::RELAY_WRITE_FAILED));
            throw;
        }
    }

    net::awaitable<tl::expected<void, common::ErrorCode>>
    WritePayloadFrames(uint32_t sid, LogicalStream& logical, buf::MultiBuffer mb) {
        auto write_lease = write_gate.TryAcquire();
        if (!write_lease) write_lease = co_await write_gate.Acquire();
        if (!write_lease || closed || !stream) {
            mb.clear();
            co_return tl::unexpected(ClosedError());
        }

        logical.CheckWrite();

        try {
            const uint32_t this_packet = NextPacketIndex();
            const auto scheme_guard = SchemeGuardFor(this_packet);
            auto ok = co_await WriteMultiBufferAsFramesWithPadding(
                *stream, *scheme_, this_packet, kCmdPSH, sid, std::move(mb));
            if (!ok) {
                CloseAll(ok.error());
                co_return tl::unexpected(ok.error());
            }
            co_return tl::expected<void, common::ErrorCode>{};
        } catch (...) {
            CloseAll(transport::ClassifyFailure(std::current_exception(), common::ErrorCode::RELAY_WRITE_FAILED));
            throw;
        }
    }

    net::awaitable<tl::expected<void, common::ErrorCode>>
    WritePayloadBuffers(uint32_t sid, LogicalStream& logical, std::span<const net::const_buffer> buffers) {
        bool has_data = false;
        for (const net::const_buffer& buffer : buffers) {
            if (buffer.data() && buffer.size() > 0) {
                has_data = true;
                break;
            }
        }
        if (!has_data) {
            co_return tl::expected<void, common::ErrorCode>{};
        }

        auto write_lease = write_gate.TryAcquire();
        if (!write_lease) write_lease = co_await write_gate.Acquire();
        if (!write_lease || closed || !stream) {
            co_return tl::unexpected(ClosedError());
        }

        logical.CheckWrite();

        try {
            const uint32_t this_packet = NextPacketIndex();
            const auto scheme_guard = SchemeGuardFor(this_packet);
            auto ok = co_await WriteBuffersAsFramesWithPadding(
                *stream, *scheme_, this_packet, kCmdPSH, sid, buffers);
            if (!ok) {
                CloseAll(ok.error());
                co_return tl::unexpected(ok.error());
            }
            co_return tl::expected<void, common::ErrorCode>{};
        } catch (...) {
            CloseAll(transport::ClassifyFailure(std::current_exception(), common::ErrorCode::RELAY_WRITE_FAILED));
            throw;
        }
    }

    net::awaitable<tl::expected<void, common::ErrorCode>>
    WriteFrameSerialized(uint8_t cmd, uint32_t sid, std::span<const uint8_t> payload) {
        auto write_lease = write_gate.TryAcquire();
        if (!write_lease) write_lease = co_await write_gate.Acquire();
        if (!write_lease || closed || !stream) {
            co_return tl::unexpected(ClosedError());
        }
        if (cmd == kCmdFIN) {
            const auto found = logical_streams.find(sid);
            if (found != logical_streams.end()) {
                if (auto logical = found->second.lock(); logical && logical->RemoteClosed())
                    co_return tl::expected<void, common::ErrorCode>{};
            }
        }

        try {
            auto ok = co_await WriteFrame(*stream, cmd, sid, payload);
            if (!ok) {
                CloseAll(ok.error());
                co_return tl::unexpected(ok.error());
            }
            co_return tl::expected<void, common::ErrorCode>{};
        } catch (...) {
            CloseAll(transport::ClassifyFailure(std::current_exception(), common::ErrorCode::RELAY_WRITE_FAILED));
            throw;
        }
    }

    net::awaitable<void> Run() {
        while (!closed && stream) {
            auto header = co_await ReadFrameHeader(*stream);
            if (!header) {
                CloseAll(header.error());
                co_return;
            }

            const bool supports_v2 = session_version == SessionVersion::V2;
            if (header->cmd == kCmdSettings || header->cmd == kCmdSYN ||
                ((header->cmd == kCmdServerSettings || header->cmd == kCmdUpdatePaddingScheme) && header->sid != 0) ||
                ((header->cmd == kCmdHeartRequest || header->cmd == kCmdHeartResponse) &&
                    (!supports_v2 || header->sid != 0 || header->length != 0)) ||
                (header->cmd == kCmdSYNACK && (!supports_v2 || header->sid == 0))) {
                CloseAll(common::ErrorCode::PROTOCOL_INVALID_COMMAND);
                co_return;
            }

            auto discard_current = [&]() -> net::awaitable<tl::expected<void, common::ErrorCode>> {
                return DiscardFramePayload(*stream, header->length);
            };

            if (header->sid == 0) {
                switch (header->cmd) {
                    case kCmdWaste:
                        if (auto ok = co_await discard_current(); !ok) {
                            CloseAll(ok.error());
                            co_return;
                        }
                        break;
                    case kCmdServerSettings: {
                        if (session_version) {
                            CloseAll(common::ErrorCode::PROTOCOL_INVALID_COMMAND);
                            co_return;
                        }
                        auto text = co_await ReadFrameText(*stream, header->length);
                        if (!text) { CloseAll(text.error()); co_return; }
                        auto parsed = ParsePeerSettings(*text);
                        if (!parsed) { CloseAll(parsed.error()); co_return; }
                        session_version = parsed->version;
                        break;
                    }
                    case kCmdUpdatePaddingScheme: {
                        if (header->length > 0) {
                            auto text = co_await ReadFrameText(*stream, header->length);
                            if (!text) {
                                CloseAll(text.error());
                                co_return;
                            }
                            if (auto parsed = ParsePaddingScheme(*text)) {
                                scheme_ = std::make_shared<const PaddingScheme>(
                                    std::move(*parsed));
                                padding_state_->Publish(scheme_);
                            }
                        }
                        break;
                    }
                    case kCmdHeartResponse:
                        break;
                    case kCmdHeartRequest:
                        if (auto ok = co_await WriteFrameSerialized(kCmdHeartResponse, 0, {}); !ok) {
                            CloseAll(ok.error());
                            co_return;
                        }
                        break;
                    case kCmdAlert: {
                        (void)co_await DiscardFramePayload(*stream, header->length);
                        CloseAll(common::ErrorCode::PROTOCOL_DECODE_FAILED);
                        co_return;
                    }
                    default:
                        CloseAll(common::ErrorCode::PROTOCOL_INVALID_COMMAND);
                        co_return;
                }
                continue;
            }

            if ((header->sid >= next_sid && !sid_exhausted) ||
                (header->cmd != kCmdSYNACK && header->cmd != kCmdWaste &&
                 header->cmd != kCmdPSH && header->cmd != kCmdFIN &&
                 header->cmd != kCmdAlert)) {
                CloseAll(common::ErrorCode::PROTOCOL_INVALID_COMMAND);
                co_return;
            }

            std::shared_ptr<LogicalStream> logical;
            auto stream_it = logical_streams.find(header->sid);
            logical = stream_it == logical_streams.end()
                ? std::shared_ptr<LogicalStream>{}
                : stream_it->second.lock();
            if (!logical && stream_it != logical_streams.end()) {
                logical_streams.erase(stream_it);
            }
            if (!logical) {
                if (auto ok = co_await discard_current(); !ok) {
                    CloseAll(ok.error());
                    co_return;
                }
                continue;
            }

            // A failed payload read leaves the physical stream at an unknown
            // frame boundary, so it retires the session, not only this stream.
            switch (header->cmd) {
                case kCmdSYNACK:
                    if (header->length > 0) {
                        if (auto ok = co_await DiscardFramePayload(*stream, header->length); !ok) {
                            CloseAll(ok.error());
                            co_return;
                        }
                        logical->Close(common::ErrorCode::PROTOCOL_DECODE_FAILED);
                    } else {
                        logical->AckSyn();
                    }
                    break;
                case kCmdWaste:
                    if (auto ok = co_await discard_current(); !ok) {
                        CloseAll(ok.error());
                        co_return;
                    }
                    break;
                case kCmdPSH: {
                    auto payload = co_await ReadFramePayload(*stream, header->length);
                    if (!payload) {
                        CloseAll(payload.error());
                        co_return;
                    }
                    co_await logical->PushPayload(std::move(*payload));
                    break;
                }
                case kCmdFIN:
                    if (auto ok = co_await discard_current(); !ok) {
                        CloseAll(ok.error());
                        co_return;
                    }
                    logical->CloseRemote();
                    break;
                case kCmdAlert: {
                    if (auto ok = co_await DiscardFramePayload(*stream, header->length); !ok) {
                        CloseAll(ok.error());
                        co_return;
                    }
                    logical->Close(common::ErrorCode::PROTOCOL_DECODE_FAILED);
                    break;
                }
                default:
                    CloseAll(common::ErrorCode::PROTOCOL_INVALID_COMMAND);
                    co_return;
            }
        }
    }
};

// Stable admission-namespace pool. A checkout is busy before any
// suspension. The host owns only pool metadata and task completion accounting;
// every reader, writer and negotiated state belongs to the physical domain.
class Handler::SessionPool final
    : public std::enable_shared_from_this<SessionPool>
    , public transport::internet::TimeoutEvent {
    using Clock = std::chrono::steady_clock;

    struct Entry {
        std::shared_ptr<ClientSession> session;
        std::optional<Clock::time_point> idle_since;
    };

    static void Close(const std::shared_ptr<ClientSession>& session,
                      common::ErrorCode error = common::ErrorCode::CANCELLED) noexcept {
        if (!session) return;
        session->CloseAll(error);
    }

public:
    class Lease {
    public:
        Lease() = default;
        Lease(const Lease&) = delete;
        Lease& operator=(const Lease&) = delete;
        Lease(Lease&& other) noexcept = default;
        Lease& operator=(Lease&& other) noexcept {
            if (this != &other) {
                Discard();
                pool_ = std::move(other.pool_);
                session_ = std::move(other.session_);
                reusable_ = std::exchange(other.reusable_, false);
            }
            return *this;
        }
        ~Lease() noexcept { Discard(); }

        [[nodiscard]] const std::shared_ptr<ClientSession>& Get() const noexcept { return session_; }

        void Reuse() noexcept { reusable_ = true; }

    private:
        friend class SessionPool;
        Lease(std::shared_ptr<SessionPool> pool, std::shared_ptr<ClientSession> session) noexcept
            : pool_(std::move(pool)), session_(std::move(session)) {}
        void Discard() noexcept {
            if (!pool_ || !session_) return;
            auto pool = std::move(pool_);
            auto session = std::move(session_);
            if (reusable_) pool->Release(session);
            else pool->Remove(session);
        }
        std::shared_ptr<SessionPool> pool_;
        std::shared_ptr<ClientSession> session_;
        bool reusable_ = false;
    };

    SessionPool(net::io_context& io_context, common::AwaitableTaskGroup& owner_tasks,
                Clock::duration check, Clock::duration timeout,
                size_t minimum, std::string_view name)
        : TimeoutEvent(io_context)
        , tasks_(owner_tasks)
        , check_interval_(check)
        , idle_timeout_(timeout)
        , minimum_idle_(minimum)
        , tag_(name) {
        if (check <= Clock::duration::zero() || timeout <= Clock::duration::zero()) {
            throw std::invalid_argument("AnyTLS session intervals must be positive");
        }
    }
    SessionPool(const SessionPool&) = delete;
    SessionPool& operator=(const SessionPool&) = delete;

    template<class Accept>
    [[nodiscard]] Lease AcquireIf(Accept&& accept) {
        CheckActive();
        Prune();
        for (auto it = entries_.rbegin(); it != entries_.rend(); ++it) {
            if (it->idle_since && accept(*it->session)) {
                it->idle_since.reset();
                return Lease(this->shared_from_this(), it->session);
            }
        }
        return {};
    }

    [[nodiscard]] Lease Acquire() {
        return AcquireIf([](const ClientSession&) { return true; });
    }

    [[nodiscard]] Lease Adopt(std::shared_ptr<ClientSession> session) {
        try {
            CheckActive();
            if (!session) {
                throw std::invalid_argument("cannot adopt a closed AnyTLS session");
            }
            entries_.push_back({session, std::nullopt});
            if (!Valid()) Schedule();
            Start(session);
            return Lease(this->shared_from_this(), std::move(session));
        } catch (...) {
            Remove(session);
            throw;
        }
    }

    void Retire() noexcept {
        retired_ = true;
        Cancel();
        std::vector<Entry> closing(entries_.get_allocator());
        closing.swap(entries_);
        for (const auto& entry : closing) Close(entry.session);
    }

private:
    void CheckActive() const {
        if (failure_) std::rethrow_exception(failure_);
        if (retired_) throw std::logic_error("AnyTLS session pool is retired");
    }

    void Remove(const std::shared_ptr<ClientSession>& session) noexcept {
        // Keep an owner while erasing the index, before cancellation can
        // notify logical requests or finish the physical operation.
        const auto closing = session;
        std::erase_if(entries_, [&](const auto& entry) { return entry.session == session; });
        StopIfEmpty();
        Close(closing);
    }

    void Start(const std::shared_ptr<ClientSession>& session) {
        tasks_.Spawn(RunPhysical(this->shared_from_this(), session));
    }

    // A resident group child must contain every failure: an escaping
    // exception would stop all physical sessions of this Worker.
    static net::awaitable<void> RunPhysical(std::shared_ptr<SessionPool> owner,
                                            std::shared_ptr<ClientSession> session) {
        std::exception_ptr failure;
        try {
            auto cancellation = co_await net::this_coro::cancellation_state;
            cancellation.slot().assign([session](net::cancellation_type type) {
                if (type != net::cancellation_type::none) Close(session);
            });
            struct ClearSlot {
                net::cancellation_slot slot;
                ~ClearSlot() { slot.clear(); }
            } clear{cancellation.slot()};
            co_await session->Run();
        } catch (...) {
            failure = std::current_exception();
        }
        const common::ErrorCode error = failure ? transport::ClassifyFailure(failure, common::ErrorCode::INTERNAL)
                                        : common::ErrorCode::CONNECTION_CLOSED;
        // A loop that returned or threw must never remain reusable.
        // CloseAll retains the first terminal cause.
        Close(session, error);
        owner->Remove(session);
        if (failure && error != common::ErrorCode::CANCELLED &&
            error != common::ErrorCode::CONNECTION_CLOSED && error != common::ErrorCode::SOCKET_EOF) {
            try {
                LOG_WARN("AnyTLS outbound '{}': physical session task failed: {}",
                    owner->tag_, common::ErrorCodeToString(error));
            } catch (...) {}
        }
    }

    void Release(const std::shared_ptr<ClientSession>& session) noexcept {
        auto it = std::find_if(entries_.begin(), entries_.end(),
            [&](const auto& entry) { return entry.session == session; });
        if (retired_ || it == entries_.end()) {
            Remove(session);
            return;
        }
        it->idle_since = Clock::now();
        // Keep most recently returned idle sessions at the back, without
        // allocating a second list or changing the ownership count.
        std::rotate(it, it + 1, entries_.end());
    }

    void Prune() noexcept {
        const auto now = Clock::now();
        size_t retained_idle = 0;
        for (size_t i = entries_.size(); i-- > 0;) {
            const auto& entry = entries_[i];
            bool remove = false;
            if (entry.idle_since) {
                if (retained_idle >= minimum_idle_ &&
                    now - *entry.idle_since >= idle_timeout_) {
                    remove = true;
                } else {
                    ++retained_idle;
                }
            }
            if (remove) {
                const auto closing = entry.session;
                entries_.erase(entries_.begin() + static_cast<std::ptrdiff_t>(i));
                Close(closing);
            }
        }
        StopIfEmpty();
    }

    void StopIfEmpty() noexcept {
        if (!entries_.empty()) return;
        Cancel();
        std::vector<Entry>{entries_.get_allocator()}.swap(entries_);
    }

    void Schedule() {
        if (!ScheduleAfter(std::chrono::ceil<std::chrono::milliseconds>(check_interval_)))
            throw IoSystemError(io_error::operation_aborted);
    }

    void OnTimeout() noexcept override {
        // Pruning can drop the last indexed session and notify its users.
        // Keep this event's owner alive until rescheduling has finished.
        const auto self = this->shared_from_this();
        if (retired_) return;
        try {
            Prune();
            if (!entries_.empty()) Schedule();
        } catch (...) {
            failure_ = std::current_exception();
            Retire();
            try {
                LOG_ERROR("AnyTLS outbound '{}': idle session scheduler failed", tag_);
            } catch (...) {}
        }
    }

    common::AwaitableTaskGroup& tasks_;
    const Clock::duration check_interval_;
    const Clock::duration idle_timeout_;
    const size_t minimum_idle_;
    const std::string tag_;
    std::vector<Entry> entries_;
    bool retired_ = false;
    std::exception_ptr failure_;
};

struct Handler::LogicalStreamLease {
    bool& reusable;
    std::shared_ptr<ClientSession> session;
    std::shared_ptr<ClientSession::LogicalStream> logical;
    uint32_t sid = 0;
    bool cleaned = false;

    LogicalStreamLease(
        bool& reusable,
        std::shared_ptr<ClientSession> session,
        std::shared_ptr<ClientSession::LogicalStream> logical,
        uint32_t sid) noexcept
        : reusable(reusable)
        , session(std::move(session))
        , logical(std::move(logical))
        , sid(sid) {
        ++this->session->active_streams;
    }

    ~LogicalStreamLease() noexcept { Cleanup(common::ErrorCode::CANCELLED); }

    LogicalStreamLease(const LogicalStreamLease&) = delete;
    LogicalStreamLease& operator=(const LogicalStreamLease&) = delete;

    void Finish(common::ErrorCode error) noexcept {
        Cleanup(error);
        reusable = error == common::ErrorCode::OK && session->Available();
    }

private:
    void Cleanup(common::ErrorCode error) noexcept {
        if (cleaned) return;
        cleaned = true;
        session->UnregisterLogicalStream(sid);
        logical->Close(error);
        if (session->active_streams > 0) --session->active_streams;
    }
};
namespace {

net::awaitable<tl::expected<std::unique_ptr<transport::AsyncStream>, common::ErrorCode>>
DialPhysicalSession(
    transport::internet::OutboundDialer& dialer,
    const infra::AnyTlsSettings& settings,
    const transport::internet::OutboundDialer::OrderedBind* ordered_bind,
    std::chrono::seconds handshake_timeout,
    const PaddingScheme& opening_scheme,
    session::Context& ctx) {
    auto dialed = co_await dialer.Dial(ctx, settings.server, ordered_bind);
    if (!dialed) {
        co_return tl::unexpected(dialed.error());
    }

    auto new_stream = std::move(*dialed);

    new_stream->SetIdleTimeout(handshake_timeout);
    auto deadline = new_stream->StartPhaseDeadline(handshake_timeout);

    const uint16_t auth_padding_size = opening_scheme.SampleAuthPaddingSize();

    const size_t auth_packet_size = ::proxy::anytls::kAuthPrefixSize + static_cast<size_t>(auth_padding_size);
    std::array<uint8_t, 256> inline_auth{};
    std::vector<uint8_t> heap_auth;
    common::ScopedCleanse cleanse_auth_packet{inline_auth, heap_auth};
    uint8_t* auth_ptr = inline_auth.data();
    if (auth_packet_size > inline_auth.size()) {
        heap_auth.assign(auth_packet_size, uint8_t{0});
        auth_ptr = heap_auth.data();
    }
    std::copy(settings.password_hash.begin(), settings.password_hash.end(), auth_ptr);
    auth_ptr[32] = static_cast<uint8_t>(auth_padding_size >> 8);
    auth_ptr[33] = static_cast<uint8_t>(auth_padding_size);

    tl::expected<void, common::ErrorCode> ok;
    try {
        ok = co_await WriteAll(
            *new_stream,
            std::span<const uint8_t>(auth_ptr, auth_packet_size));
    } catch (...) {
        new_stream->CloseAbortive();
        throw;
    }
    if (!ok) {
        const bool timed_out =
            proxy::ConsumeOutboundHandshakeTimeout(*new_stream, deadline);
        new_stream->CloseAbortive();
        co_return tl::unexpected(timed_out ? common::ErrorCode::TIMEOUT : ok.error());
    }
    co_return std::move(new_stream);
}

tl::expected<std::vector<uint8_t>, common::ErrorCode> BuildOpenPacket(
    uint32_t sid,
    bool is_udp,
    const common::TargetAddress& original_target,
    common::ForwardedMetadataView forwarded,
    const PaddingScheme* opening_scheme) {
    const common::TargetAddress uot_magic_target = is_udp
        ? common::TargetAddress(proxy::uot::kMagicAddress, 0)
        : common::TargetAddress{};
    const common::TargetAddress& stream_target = is_udp ? uot_magic_target : original_target;
    std::array<uint8_t, common::kMaxEncodedAddressSize> target{};
    const size_t target_size = (stream_target.IsValid() ||
        proxy::uot::VersionFromMagicAddress(stream_target))
        ? common::EncodeAddressTo(stream_target, target.data(), target.size(),
                          common::AddressWireFormat::Socks5, forwarded) : 0;
    if (target_size == 0) {
        return tl::unexpected(common::ErrorCode::INVALID_ARGUMENT);
    }

    std::vector<uint8_t> packet;
    packet.reserve((kFrameHeaderSize * 4) + 64 + target_size + 128);
    if (opening_scheme) {
        const auto settings = ClientSettings(*opening_scheme);
        auto settings_frame = AppendFrameBytesTo(
            packet,
            kCmdSettings,
            0,
            std::span<const uint8_t>(
                reinterpret_cast<const uint8_t*>(settings.data()), settings.size()));
        if (!settings_frame) {
            return tl::unexpected(settings_frame.error());
        }
    }
    auto syn_frame = AppendFrameBytesTo(packet, kCmdSYN, sid, {});
    auto target_frame = AppendFrameBytesTo(
        packet,
        kCmdPSH,
        sid,
        std::span<const uint8_t>(target.data(), target_size));
    if (!syn_frame || !target_frame) {
        return tl::unexpected(common::ErrorCode::PROTOCOL_ENCODE_FAILED);
    }
    if (is_udp) {
        auto request = proxy::uot::EncodeRequest(true, original_target, forwarded);
        if (!request) {
            return tl::unexpected(request.error());
        }
        auto request_frame = AppendFrameBytesTo(
            packet,
            kCmdPSH,
            sid,
            request->span());
        if (!request_frame) {
            return tl::unexpected(request_frame.error());
        }
    }
    return packet;
}

}  // namespace


Handler::Handler(std::string_view tag,
                 net::io_context& io_context,
                 std::shared_ptr<const infra::AnyTlsSettings> settings,
                 common::AwaitableTaskGroup& tasks)
    : tag_(tag)
    , settings_(std::move(settings))
    , padding_(std::make_shared<PaddingState>())
    , pool_(std::make_shared<SessionPool>(
          io_context, tasks, settings_->idle_session_check_interval,
          settings_->idle_session_timeout, settings_->min_idle_sessions, tag_)) {}

Handler::~Handler() noexcept {
    if (pool_) pool_->Retire();
}

net::awaitable<OutboundProcessResult> Handler::Process(
    session::Context& ctx,
    transport::Link inbound,
    transport::internet::OutboundDialer& dialer,
    const infra::TimeoutsConfig& timeouts,
    app::StatsShard& stats,
    const app::RelayConfig& relay_config,
    buf::MultiBufferBatch first_payload) {
    if (!inbound.Valid()) {
        co_return tl::unexpected(common::ErrorCode::PROTOCOL_DECODE_FAILED);
    }
    const auto ordered_bind = dialer.SelectOrderedBind(ctx);
    std::shared_ptr<const PaddingScheme> opening_scheme;
    SessionPool::Lease transport_lease;
    std::shared_ptr<ClientSession> session;
    bool reusable = false;
    std::exception_ptr failure;
    OutboundProcessResult result = tl::unexpected(common::ErrorCode::INTERNAL);
    try {
        opening_scheme = padding_->scheme;
        transport_lease = ordered_bind
            ? pool_->AcquireIf([&](const ClientSession& physical) {
                const auto& remote = physical.remote_endpoint;
                const auto& local = physical.local_endpoint;
                if (!remote || !local) return false;
                const auto& selected = remote->address().is_v6()
                    ? ordered_bind->v6 : ordered_bind->v4;
                return !selected.address ||
                    iputil::NormalizeAddress(local->address()) == *selected.address;
            })
            : pool_->Acquire();
        session = transport_lease.Get();
        if (!session) {
            auto dialed = co_await DialPhysicalSession(dialer, *settings_,
                ordered_bind ? &*ordered_bind : nullptr, timeouts.HandshakeTimeout(),
                *opening_scheme, ctx);
            if (!dialed) {
                result = tl::unexpected(dialed.error());
            } else {
                session = std::make_shared<ClientSession>(
                    dialer.IoContext(), std::move(*dialed), padding_,
                    std::move(opening_scheme));
                transport_lease = pool_->Adopt(session);
            }
        }
        if (session) {
            result = co_await ProcessSession(ctx, inbound, dialer, timeouts, stats, relay_config,
                std::move(first_payload), session, reusable);
        }
    } catch (...) {
        failure = std::current_exception();
    }
    co_await net::this_coro::reset_cancellation_state(net::disable_cancellation());
    session.reset();
    if (reusable && !failure) transport_lease.Reuse();
    if (failure) std::rethrow_exception(failure);
    co_return result;
}

net::awaitable<OutboundProcessResult> Handler::ProcessSession(
    session::Context& ctx, transport::Link inbound, transport::internet::OutboundDialer& dialer,
    const infra::TimeoutsConfig& timeouts, app::StatsShard& stats, const app::RelayConfig& relay_config,
    buf::MultiBufferBatch first_payload,
    std::shared_ptr<ClientSession> session, bool& reusable) {
    if (session->IsClosed()) co_return tl::unexpected(session->ClosedError());
    if (session->next_sid != 1) {
        LOG_CONN_DEBUG(ctx, "reusing idle session sid={}", session->next_sid);
        dialer.RecordConnected(ctx, *session->stream);
    }

    if (!session || !session->stream) {
        co_return tl::unexpected(common::ErrorCode::INTERNAL);
    }
    if (session->sid_exhausted) {
        co_return tl::unexpected(common::ErrorCode::RESOURCE_EXHAUSTED);
    }

    auto& stream = *session->stream;
    const uint32_t sid = session->AllocateSid();
    auto logical = session->RegisterLogicalStream(sid);
    LogicalStreamLease logical_lease(reusable, session, logical, sid);
    const bool is_udp = ctx.content.network == common::Network::UDP;
    const common::TargetAddress& original_target = ctx.outbound.target;
    auto open_logical_stream = [&]() -> net::awaitable<tl::expected<void, common::ErrorCode>> {
        stream.SetIdleTimeout(timeouts.HandshakeTimeout());
        auto deadline = stream.StartPhaseDeadline(timeouts.HandshakeTimeout());
        auto open_packet = BuildOpenPacket(
            sid, is_udp, original_target, dialer.ForwardedMetadata(ctx),
            session->opening_scheme_.get());
        if (!open_packet) {
            stream.ClearPhaseDeadline();
            session->CloseAll(open_packet.error());
            co_return tl::unexpected(open_packet.error());
        }
        if (auto ok = co_await session->WriteOpenPacket(std::move(*open_packet)); !ok) {
            const bool timed_out =
                proxy::ConsumeOutboundHandshakeTimeout(stream, deadline);
            const common::ErrorCode error = timed_out ? common::ErrorCode::TIMEOUT : ok.error();
            stream.Cancel();
            logical->Close(error);
            co_return tl::unexpected(error);
        }
        if (sid >= 2 && session->session_version == SessionVersion::V2) {
            if (auto ok = co_await logical->WaitOpenResult(kSynAckTimeout, dialer.IoContext()); !ok) {
                const bool timed_out =
                    proxy::ConsumeOutboundHandshakeTimeout(stream, deadline);
                const common::ErrorCode error = timed_out ? common::ErrorCode::TIMEOUT : ok.error();
                session->CloseAll(error);
                co_return tl::unexpected(error);
            }
        }
        co_return tl::expected<void, common::ErrorCode>{};
    };
    if (auto ok = co_await open_logical_stream(); !ok) {
        co_return tl::unexpected(ok.error());
    }
    // A pool lease exclusively owns this physical session for the request.
    // Its background reader must observe the same deadlines as relay writes.
    stream.SetIdleTimeout(relay_config.idle_timeout);
    stream.SetReadTimeout(std::chrono::seconds(0));
    stream.SetWriteTimeout(relay_config.write_timeout);
    stream.ClearPhaseDeadline();

    struct LogicalEndpoint final : transport::MultiBufferReader,
                                   transport::MultiBufferWriter {
        ClientSession& session;
        ClientSession::LogicalStream& logical;
        uint32_t sid = 0;
        bool cancelled = false;
        size_t pending_writes = 0;

        struct PendingWrite {
            size_t& count;
            explicit PendingWrite(size_t& count) noexcept : count(count) { ++count; }
            ~PendingWrite() noexcept { --count; }
            PendingWrite(const PendingWrite&) = delete;
            PendingWrite& operator=(const PendingWrite&) = delete;
        };

        LogicalEndpoint(ClientSession& s,
                        ClientSession::LogicalStream& l,
                        uint32_t stream_id) noexcept
            : session(s)
            , logical(l)
            , sid(stream_id) {}

        net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
            auto payload = co_await logical.ReadPayload();
            if (!payload) {
                if (payload.error() == common::ErrorCode::OK) {
                    co_return buf::MultiBuffer{};
                }
                throw transport::LinkError(payload.error());
            }
            co_return std::move(*payload);
        }

        transport::EofAction ReadEofAction() const noexcept override { return transport::EofAction::CloseLink; }
        bool WriteShutdownClosesLink() const noexcept override { return true; }

        net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer mb) override {
            if (mb.byte_size() == 0) {
                co_return;
            }
            if (cancelled) {
                throw transport::LinkError(common::ErrorCode::CANCELLED);
            }
            logical.CheckWrite();

            PendingWrite pending(pending_writes);
            auto ok = co_await session.WritePayloadFrames(sid, logical, std::move(mb));
            if (!ok) {
                logical.Close(ok.error());
                throw transport::LinkError(ok.error());
            }
        }

        net::awaitable<void> WriteBuffers(std::span<const net::const_buffer> buffers) override {
            if (cancelled) {
                throw transport::LinkError(common::ErrorCode::CANCELLED);
            }
            logical.CheckWrite();
            PendingWrite pending(pending_writes);
            auto ok = co_await session.WritePayloadBuffers(sid, logical, buffers);
            if (!ok) {
                logical.Close(ok.error());
                throw transport::LinkError(ok.error());
            }
        }

        net::awaitable<void> AsyncShutdownWrite() override {
            if (!cancelled && logical.BeginLocalClose()) {
                PendingWrite pending(pending_writes);
                if (auto ok = co_await session.WriteFrameSerialized(kCmdFIN, sid, {}); !ok) {
                    throw transport::LinkError(ok.error());
                }
            }
        }

        transport::CancellationSource& Cancellation() noexcept override { return logical.Cancellation(); }

        void Cancel() noexcept {
            cancelled = true;
            logical.Close(common::ErrorCode::CANCELLED);
            // Relay also calls Cancel after a successful join. Preserve that
            // idle transport, but abort a pending gate/write: a partial frame
            // cannot safely be handed to the next request.
            if (pending_writes != 0) session.CloseAll(common::ErrorCode::CANCELLED);
        }

        void SetIdleTimeout(std::chrono::seconds timeout) {
            session.stream->SetIdleTimeout(timeout);
        }
        void SetReadTimeout(std::chrono::seconds timeout) {
            session.stream->SetReadTimeout(timeout);
        }
        void SetWriteTimeout(std::chrono::seconds timeout) {
            session.stream->SetWriteTimeout(timeout);
        }
        transport::PhaseDeadlineHandle StartPhaseDeadline(std::chrono::seconds timeout) {
            return session.stream->StartPhaseDeadline(timeout);
        }
        void ClearPhaseDeadline() { session.stream->ClearPhaseDeadline(); }
        bool ConsumeIdleTimeout() noexcept { return session.stream->ConsumeIdleTimeout(); }
        bool ConsumeReadTimeout() noexcept { return session.stream->ConsumeReadTimeout(); }
        bool ConsumeWriteTimeout() noexcept { return session.stream->ConsumeWriteTimeout(); }
        bool ConsumePhaseDeadline() noexcept { return session.stream->ConsumePhaseDeadline(); }
    };

    LogicalEndpoint target_endpoint(
        *session,
        *logical,
        sid);

    app::RelayResult result;
    auto relay_endpoint = [&](auto& endpoint) {
        return app::DoRelayLink(
            dialer.IoContext(), *inbound.reader, *inbound.writer, inbound.control,
            endpoint, ctx, stats, relay_config, std::move(first_payload));
    };

    if (is_udp) {
        proxy::uot::FramedEndpoint uot_endpoint(
            target_endpoint, true, original_target);
        result = co_await relay_endpoint(uot_endpoint);
    } else {
        result = co_await relay_endpoint(target_endpoint);
    }

    if (result.error == common::ErrorCode::OK) {
        // Request and half-close deadlines must not escape into the idle pool.
        stream.SetIdleTimeout(std::chrono::seconds(0));
        stream.SetReadTimeout(std::chrono::seconds(0));
        stream.SetWriteTimeout(std::chrono::seconds(0));
        stream.ClearPhaseDeadline();
    }
    logical_lease.Finish(result.error);
    co_return result;
}

}  // namespace proxy::anytls::outbound

namespace {
const bool kOutboundRegistered = (::proxyman::outbound::RegisterProxy(
    ::constants::protocol::kAnyTLS,
    [](const ::infra::OutboundSourceConfig& cfg)
        -> std::optional<::proxyman::outbound::PreparedOutboundProxy> {
        const auto* settings = std::get_if<::infra::AnyTlsSettings>(&cfg.settings);
        if (!settings) return std::nullopt;
        auto stream_settings = ::proxy::PrepareOutboundStream(
            cfg,
            settings->server,
            ::transport::internet::OutboundStreamDefaults{
                .require_tls = true,
                .fallback_server_name = {},
                .allow_insecure = false,
                .alpn = {},
            });
        return ::proxyman::outbound::PreparedOutboundProxy{
            .create = ::proxyman::outbound::MakePreparedOutboundCreator<
                ::infra::AnyTlsSettings,
                +[](std::string_view tag,
                    std::shared_ptr<const ::infra::AnyTlsSettings> state,
                    ::net::io_context& io_context,
                    ::common::AwaitableTaskGroup& tasks) -> std::unique_ptr<::proxy::Outbound> {
                    return std::make_unique<::proxy::anytls::outbound::Handler>(
                        tag, io_context, std::move(state), tasks);
                }>(*settings),
            .sender = ::transport::internet::OutboundSenderSettings{
                .stream_settings = std::move(stream_settings),
                .send_through = {},
            },
        };
    }), true);
}  // namespace
