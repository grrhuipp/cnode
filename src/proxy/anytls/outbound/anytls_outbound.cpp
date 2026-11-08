#include "anytls_outbound.hpp"
#include "common/address_codec.hpp"
#include "anytls_outbound_settings.hpp"
#include "../../../common/awaitable_task_group.hpp"

#include "../anytls_codec.hpp"
#include "../padding.hpp"
#include "common/buf/length_prefixed_packet_buffer.hpp"
#include "../../outbound_server.hpp"
#include "../../handshake_timeout.hpp"
#include "../../uot/uot.hpp"
#include "transport/internet/async_write_gate.hpp"
#include "app/dns/dns.hpp"
#include "app/session_group_executor.hpp"
#include "app/relay.hpp"
#include "app/stats.hpp"
#include "common/allocator.hpp"
#include "common/ip_utils.hpp"
#include "common/container_util.hpp"
#include "common/session.hpp"
#include "infra/log.hpp"
#include "infra/runtime_failure.hpp"
#include "infra/config_types.hpp"
#include "app/proxyman/outbound/factory.hpp"
#include "../../../app/proxyman/outbound/registration.hpp"
#include "transport/internet/outbound_target_builder.hpp"
#include "transport/internet/timeout_scheduler.hpp"
#include "transport/link_error.hpp"

#include <asio/experimental/channel.hpp>
#include <asio/dispatch.hpp>
#include <openssl/crypto.h>
#include <algorithm>
#include <chrono>
#include <exception>
#include <limits>
#include <new>
#include <stdexcept>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace {

constexpr size_t kMaxLogicalQueuedPayloadBytes = ::anytls::kMaxFramePayload;
// anytls-go Session.OpenStream: a v2 stream with sid >= 2 must see SYNACK
// within 3 s or the whole session closes (proxy/session/session.go).
constexpr std::chrono::seconds kSynAckTimeout{3};

}  // namespace

namespace proxy::anytls::outbound {

using namespace ::anytls;

namespace {

// Classify before CloseAll broadcasts cancellation to logical consumers. An
// unknown physical write failure must not arrive at a relay as a read failure.
ErrorCode SessionExceptionError(const std::exception_ptr& failure,
                               ErrorCode unknown = ErrorCode::INTERNAL) noexcept {
    try { std::rethrow_exception(failure); }
    catch (const transport::LinkError& e) { return e.code(); }
    catch (const std::bad_alloc&) { return ErrorCode::RESOURCE_EXHAUSTED; }
    catch (const IoSystemError& e) { return MapAsioError(e.code()); }
    catch (...) { return unknown; }
}

struct PhysicalHooks final : memory::ThreadAllocated, ExecutionDomain::Hooks {
    memory::AllocationDomain allocation;
    std::optional<memory::ScopedAllocationDomain> scope;
    void Enter() noexcept override { scope.emplace(allocation); }
    void Leave() noexcept override { scope.reset(); }
    void OnFailure(std::exception_ptr) noexcept override {
        FailRuntime("AnyTLS physical domain", "uncaught execution callback failure");
    }
};

net::any_io_executor SessionExecutor(net::io_context& io) {
    if (auto domain = ExecutionDomain::Current()) return domain->Executor();
    return io.get_executor();
}

template <class T, class... Args>
[[nodiscard]] std::shared_ptr<T> AllocateWorkerShared(Args&&... args) {
    memory::ScopedWorkerAllocation worker_allocation;
    return memory::AllocateShared<T>(std::forward<Args>(args)...);
}

}  // namespace

// The cache host alone publishes and reads the next-handshake snapshot. Each
// physical reader awaits its control update (at most one outstanding per
// session); it never forwards payload or changes another session's scheme.
struct Handler::PaddingState {
    explicit PaddingState(net::io_context& io) : executor(SessionExecutor(io)) {}

    void Publish(std::shared_ptr<const PaddingScheme> next) noexcept {
        scheme = std::move(next);
    }

    const net::any_io_executor executor;
    std::shared_ptr<const PaddingScheme> scheme{DefaultPaddingScheme()};
};

struct Handler::ClientSession : memory::ThreadAllocated {
    class LogicalStream final {
    public:
        explicit LogicalStream(net::io_context& io_context)
            : io_context_(io_context)
            , syn_signal_(SessionExecutor(io_context), 1)
            , payload_signal_(SessionExecutor(io_context), 1)
            , payload_space_signal_(SessionExecutor(io_context), 1) {}

        ~LogicalStream() noexcept {
            Close(ErrorCode::CANCELLED);
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
            if (error_ != ErrorCode::OK) throw transport::LinkError(error_);
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

        void Close(ErrorCode error = ErrorCode::OK) noexcept {
            if (closed_ && (error_ != ErrorCode::OK || error == ErrorCode::OK)) return;
            // Publish the terminal state before cancellation can re-enter us.
            // An error after FIN discards unread bytes; the first error wins.
            closed_ = true;
            error_ = error;
            if (error != ErrorCode::OK) {
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

        net::awaitable<tl::expected<void, ErrorCode>> WaitOpenResult(std::chrono::seconds timeout) {
            auto result = OpenResult();
            if (!result) {
                // The finite wait owns its deadline. ACK, FIN and errors are
                // persistent state; a channel notification is only a wakeup.
                struct OpenDeadline final : TimeoutEvent {
                    explicit OpenDeadline(LogicalStream& owner) noexcept : owner(owner) {}
                    void OnTimeout() override {
                        if (!owner.OpenResult()) owner.Close(ErrorCode::TIMEOUT);
                    }
                    LogicalStream& owner;
                } deadline(*this);
                const auto domain = ExecutionDomain::Current();
                if (!deadline.ScheduleAfter(
                        std::chrono::duration_cast<std::chrono::milliseconds>(timeout),
                        domain ? domain->Reactor() : io_context_))
                    co_return tl::unexpected(ErrorCode::CANCELLED);
                do {
                    const auto [ec] = co_await syn_signal_.async_receive(
                        net::as_tuple(net::use_awaitable));
                    if (ec && !OpenResult()) Close(ErrorCode::CANCELLED);
                    result = OpenResult();
                } while (!result);
            }
            if (*result != ErrorCode::OK) co_return tl::unexpected(*result);
            co_return tl::expected<void, ErrorCode>{};
        }

        net::awaitable<tl::expected<buf::MultiBuffer, ErrorCode>> ReadPayload() {
            while (queued_payload_.empty() && !closed_) {
                auto [ec] = co_await payload_signal_.async_receive(
                    net::as_tuple(net::use_awaitable));
                if (ec) {
                    co_return tl::unexpected(ErrorCode::CANCELLED);
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

        std::optional<ErrorCode> OpenResult() const noexcept {
            if (error_ != ErrorCode::OK) return error_;
            // Clean FIN may precede the ACK. Relay still owns delivery of
            // queued bytes and completion of both application directions.
            if (closed_ || syn_acked_) return ErrorCode::OK;
            return std::nullopt;
        }

        void WakeOpenWaiter() noexcept {
            (void)syn_signal_.try_send(IoErrorCode{});
        }

        void WakePayloadReader() noexcept {
            (void)payload_signal_.try_send(IoErrorCode{});
        }

        transport::CancellationSource cancellation_;
        net::io_context& io_context_;
        SignalChannel syn_signal_;
        SignalChannel payload_signal_;
        SignalChannel payload_space_signal_;
        buf::MultiBuffer queued_payload_;
        ErrorCode error_ = ErrorCode::OK;
        bool closed_ = false;
        bool remote_closed_ = false;
        bool syn_acked_ = false;
    };

    ClientSession(net::io_context& io_context, std::unique_ptr<AsyncStream> s,
                  std::shared_ptr<PaddingState> padding_state,
                  std::shared_ptr<const PaddingScheme> opening_scheme)
        : io_context_(io_context)
        , stream(std::move(s))
        , padding_state_(std::move(padding_state))
        , opening_scheme_(std::move(opening_scheme))
        , scheme_(opening_scheme_)
        , domain(ExecutionDomain::Current())
        , local_endpoint(stream->LocalEndpoint())
        , remote_endpoint(stream->RemoteEndpoint()) {}

    net::io_context& io_context_;
    std::unique_ptr<AsyncStream> stream;
    std::shared_ptr<PaddingState> padding_state_;
    // Authentication, first settings, and first framed write use one snapshot.
    // Releasing it also records that settings have been sent successfully.
    std::shared_ptr<const PaddingScheme> opening_scheme_;
    std::shared_ptr<const PaddingScheme> scheme_;
    const std::shared_ptr<ExecutionDomain> domain;
    const std::optional<tcp::endpoint> local_endpoint;
    const std::optional<tcp::endpoint> remote_endpoint;
    uint32_t next_sid = 1;
    bool sid_exhausted = false;
    uint32_t packet_index = 1;
    std::optional<SessionVersion> session_version;
    transport::internet::AsyncWriteGate write_gate;
    ::memory::ThreadLocalUnorderedMap<
        uint32_t,
        std::weak_ptr<LogicalStream>>
        logical_streams;
    size_t active_streams = 0;
    bool closed = false;
    // First terminal cause. The physical loop can fail inline while Adopt
    // starts it, before the request registers its logical stream; requests
    // that then find the session closed report this cause, not a generic close.
    ErrorCode close_error = ErrorCode::OK;

    [[nodiscard]] bool IsClosed() const noexcept { return closed || !stream; }

    [[nodiscard]] ErrorCode ClosedError() const noexcept {
        return close_error != ErrorCode::OK ? close_error : ErrorCode::CONNECTION_CLOSED;
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
        auto logical = memory::AllocateShared<LogicalStream>(
            domain ? domain->Reactor() : io_context_);
        logical_streams[sid] = logical;
        return logical;
    }

    void UnregisterLogicalStream(uint32_t sid) {
        logical_streams.erase(sid);
        MaybeShrinkHashContainer(logical_streams, 8);
    }

    void CloseAll(ErrorCode error) noexcept {
        if (closed) return;
        closed = true;
        close_error = error;
        write_gate.Cancel();
        auto streams = std::exchange(
            logical_streams,
            ::memory::ThreadLocalUnorderedMap<uint32_t, std::weak_ptr<LogicalStream>>{
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

    net::awaitable<tl::expected<void, ErrorCode>>
    WriteOpenPacket(memory::ByteVector packet) {
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
            co_return tl::expected<void, ErrorCode>{};
        } catch (...) {
            CloseAll(SessionExceptionError(std::current_exception(), ErrorCode::RELAY_WRITE_FAILED));
            throw;
        }
    }

    net::awaitable<tl::expected<void, ErrorCode>>
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
            tl::expected<void, ErrorCode> ok;
            if (scheme_->RecordFor(this_packet).empty()) {
                ok = co_await WriteMultiBufferAsFrameBatch(
                    *stream, kCmdPSH, sid, std::move(mb));
            } else {
                auto scheme_snapshot = scheme_;
                ok = co_await WriteMultiBufferAsFramesWithPadding(
                    *stream, *scheme_snapshot, this_packet, kCmdPSH, sid, std::move(mb));
            }
            if (!ok) {
                CloseAll(ok.error());
                co_return tl::unexpected(ok.error());
            }
            co_return tl::expected<void, ErrorCode>{};
        } catch (...) {
            CloseAll(SessionExceptionError(std::current_exception(), ErrorCode::RELAY_WRITE_FAILED));
            throw;
        }
    }

    net::awaitable<tl::expected<void, ErrorCode>>
    WritePayloadBuffers(uint32_t sid, LogicalStream& logical, std::span<const net::const_buffer> buffers) {
        bool has_data = false;
        for (const net::const_buffer& buffer : buffers) {
            if (buffer.data() && buffer.size() > 0) {
                has_data = true;
                break;
            }
        }
        if (!has_data) {
            co_return tl::expected<void, ErrorCode>{};
        }

        auto write_lease = write_gate.TryAcquire();
        if (!write_lease) write_lease = co_await write_gate.Acquire();
        if (!write_lease || closed || !stream) {
            co_return tl::unexpected(ClosedError());
        }

        logical.CheckWrite();

        try {
            const uint32_t this_packet = NextPacketIndex();
            tl::expected<void, ErrorCode> ok;
            if (scheme_->RecordFor(this_packet).empty()) {
                ok = co_await WriteBuffersAsFrameBatch(*stream, kCmdPSH, sid, buffers);
            } else {
                auto scheme_snapshot = scheme_;
                ok = co_await WriteBuffersAsFramesWithPadding(
                    *stream, *scheme_snapshot, this_packet, kCmdPSH, sid, buffers);
            }
            if (!ok) {
                CloseAll(ok.error());
                co_return tl::unexpected(ok.error());
            }
            co_return tl::expected<void, ErrorCode>{};
        } catch (...) {
            CloseAll(SessionExceptionError(std::current_exception(), ErrorCode::RELAY_WRITE_FAILED));
            throw;
        }
    }

    net::awaitable<tl::expected<void, ErrorCode>>
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
                    co_return tl::expected<void, ErrorCode>{};
            }
        }

        try {
            auto ok = co_await WriteFrame(*stream, cmd, sid, payload);
            if (!ok) {
                CloseAll(ok.error());
                co_return tl::unexpected(ok.error());
            }
            co_return tl::expected<void, ErrorCode>{};
        } catch (...) {
            CloseAll(SessionExceptionError(std::current_exception(), ErrorCode::RELAY_WRITE_FAILED));
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
                CloseAll(ErrorCode::PROTOCOL_INVALID_COMMAND);
                co_return;
            }

            auto discard_current = [&]() -> net::awaitable<tl::expected<void, ErrorCode>> {
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
                            CloseAll(ErrorCode::PROTOCOL_INVALID_COMMAND);
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
                                scheme_ = AllocateWorkerShared<const PaddingScheme>(std::move(*parsed));
                                net::dispatch(padding_state_->executor,
                                    [state = padding_state_, next = scheme_]() mutable noexcept {
                                        state->Publish(std::move(next));
                                    });
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
                        CloseAll(ErrorCode::PROTOCOL_DECODE_FAILED);
                        co_return;
                    }
                    default:
                        CloseAll(ErrorCode::PROTOCOL_INVALID_COMMAND);
                        co_return;
                }
                continue;
            }

            if ((header->sid >= next_sid && !sid_exhausted) ||
                (header->cmd != kCmdSYNACK && header->cmd != kCmdWaste &&
                 header->cmd != kCmdPSH && header->cmd != kCmdFIN &&
                 header->cmd != kCmdAlert)) {
                CloseAll(ErrorCode::PROTOCOL_INVALID_COMMAND);
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
                        logical->Close(ErrorCode::PROTOCOL_DECODE_FAILED);
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
                    logical->Close(ErrorCode::PROTOCOL_DECODE_FAILED);
                    break;
                }
                default:
                    CloseAll(ErrorCode::PROTOCOL_INVALID_COMMAND);
                    co_return;
            }
        }
    }
};

// Stable admission-namespace pool. A checkout is busy before any
// suspension. The host owns only pool metadata and task completion accounting;
// every reader, writer and negotiated state belongs to the physical domain.
class Handler::SessionPool final : public memory::ThreadAllocated {
    using Clock = std::chrono::steady_clock;
    struct State;

    static void Close(const std::shared_ptr<ClientSession>& session,
                      ErrorCode error = ErrorCode::CANCELLED) noexcept {
        if (!session) return;
        if (!session->domain || session->domain->CanExecuteInline()) {
            session->CloseAll(error);
            return;
        }
        try {
            session->domain->Execute([session, error] { session->CloseAll(error); });
        } catch (...) {}
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
                state_ = std::move(other.state_);
                session_ = std::move(other.session_);
                owner_domain_ = std::move(other.owner_domain_);
                reusable_ = std::exchange(other.reusable_, false);
            }
            return *this;
        }
        ~Lease() noexcept { Discard(); }

        [[nodiscard]] const std::shared_ptr<ClientSession>& Get() const noexcept { return session_; }

        void Reuse() noexcept { reusable_ = true; }

    private:
        friend class SessionPool;
        Lease(std::shared_ptr<State> state, std::shared_ptr<ClientSession> session) noexcept
            : state_(std::move(state)), session_(std::move(session)),
              owner_domain_(state_->domain) {}
        void Discard() noexcept {
            if (!state_ || !session_) return;
            // Detach has completed: the physical domain's native owner is
            // stable until the next exclusive checkout. The original host is
            // only its configuration namespace, not its reuse destination.
            const auto executor = state_->executor;
            const auto worker = session_->domain ? session_->domain->OwnerId() : 0;
            auto release = [state = std::move(state_), session = std::move(session_),
                            reusable = reusable_, worker] {
                if (reusable) state->Release(session, worker);
                else state->Remove(session);
            };
            try {
                if (auto domain = owner_domain_.lock()) {
                    if (domain->CanExecuteInline()) release();
                    else domain->Execute(std::move(release));
                } else {
                    net::dispatch(executor, std::move(release));
                }
            } catch (...) {}
        }
        std::shared_ptr<State> state_;
        std::shared_ptr<ClientSession> session_;
        std::weak_ptr<ExecutionDomain> owner_domain_;
        bool reusable_ = false;
    };

    SessionPool(net::io_context& io_context, AwaitableTaskGroup& tasks,
                Clock::duration check_interval, Clock::duration idle_timeout,
                size_t minimum_idle, std::string_view tag)
        : state_(AllocateWorkerShared<State>(io_context, tasks, check_interval,
                                             idle_timeout, minimum_idle, tag)) {}
    SessionPool(const SessionPool&) = delete;
    SessionPool& operator=(const SessionPool&) = delete;
    ~SessionPool() noexcept { state_->Retire(); }
    [[nodiscard]] net::any_io_executor Executor() const { return state_->executor; }

    template<class Accept>
    [[nodiscard]] Lease AcquireIf(uint32_t worker, Accept&& accept) {
        state_->CheckActive();
        state_->Prune();
        for (auto it = state_->entries.rbegin(); it != state_->entries.rend(); ++it) {
            if (it->worker == worker && it->idle_since && accept(*it->session)) {
                it->idle_since.reset();
                return Lease(state_, it->session);
            }
        }
        return {};
    }

    [[nodiscard]] Lease Acquire(uint32_t worker) {
        return AcquireIf(worker, [](const ClientSession&) { return true; });
    }

    [[nodiscard]] Lease Adopt(std::shared_ptr<ClientSession> session) {
        try {
            state_->CheckActive();
            if (!session) {
                throw std::invalid_argument("cannot adopt a closed AnyTLS session");
            }
            state_->entries.push_back({session, std::nullopt,
                session->domain ? session->domain->OwnerId() : 0});
            if (!state_->Valid()) state_->Schedule();
            state_->Start(session);
            return Lease(state_, std::move(session));
        } catch (...) {
            state_->Remove(session);
            throw;
        }
    }

private:
    struct State final : std::enable_shared_from_this<State>, TimeoutEvent {
        struct Entry {
            std::shared_ptr<ClientSession> session;
            std::optional<Clock::time_point> idle_since;
            uint32_t worker;
        };

        State(net::io_context& io_context, AwaitableTaskGroup& owner_tasks,
              Clock::duration check, Clock::duration timeout,
              size_t minimum, std::string_view name)
            : domain(ExecutionDomain::Current()), executor(SessionExecutor(io_context)),
              tasks(owner_tasks), io_context(io_context),
              check_interval(check), idle_timeout(timeout),
              minimum_idle(minimum), tag(name) {
            if (check <= Clock::duration::zero() || timeout <= Clock::duration::zero()) {
                throw std::invalid_argument("AnyTLS session intervals must be positive");
            }
        }

        void CheckActive() const {
            if (failure) std::rethrow_exception(failure);
            if (retired) throw std::logic_error("AnyTLS session pool is retired");
        }

        void Remove(const std::shared_ptr<ClientSession>& session) noexcept {
            // Keep an owner while erasing the index, before cancellation can
            // notify logical requests or finish the physical operation.
            const auto closing = session;
            std::erase_if(entries, [&](const auto& entry) { return entry.session == session; });
            StopIfEmpty();
            Close(closing);
        }

        void Start(const std::shared_ptr<ClientSession>& session) {
            tasks.Spawn(RunPhysical(this->shared_from_this(), session));
        }

        // A resident group child must contain every failure: an escaping
        // exception would stop all physical sessions of this Worker.
        static net::awaitable<void> RunPhysical(std::shared_ptr<State> owner,
                                                std::shared_ptr<ClientSession> session) {
            std::exception_ptr failure;
            try {
                if (session->domain) {
                    // Cancellation is delivered as a domain control, never by
                    // touching a moved socket from the cache host's thread.
                    auto cancellation = co_await net::this_coro::cancellation_state;
                    cancellation.slot().assign([session](net::cancellation_type type) {
                        if (type != net::cancellation_type::none) Close(session);
                    });
                    struct ClearSlot {
                        net::cancellation_slot slot;
                        ~ClearSlot() { slot.clear(); }
                    } clear{cancellation.slot()};
                    // Create the resident reader frame after entering the
                    // physical domain, not in the pool's allocation arena.
                    co_await net::co_spawn(session->domain->Executor(),
                        [session]() -> net::awaitable<void> { co_await session->Run(); },
                        net::bind_cancellation_slot(net::cancellation_slot{}, net::use_awaitable));
                } else {
                    co_await session->Run();
                }
            } catch (...) {
                failure = std::current_exception();
            }
            const ErrorCode error = failure ? SessionExceptionError(failure)
                                            : ErrorCode::CONNECTION_CLOSED;
            // A loop that returned or threw must never remain reusable.
            // CloseAll retains the first terminal cause.
            Close(session, error);
            owner->Remove(session);
            if (failure && error != ErrorCode::CANCELLED &&
                error != ErrorCode::CONNECTION_CLOSED && error != ErrorCode::SOCKET_EOF) {
                try {
                    LOG_WARN("AnyTLS outbound '{}': physical session task failed: {}",
                        owner->tag, ErrorCodeToString(error));
                } catch (...) {}
            }
        }

        void Release(const std::shared_ptr<ClientSession>& session, uint32_t worker) noexcept {
            auto it = std::find_if(entries.begin(), entries.end(),
                [&](const auto& entry) { return entry.session == session; });
            if (retired || it == entries.end()) {
                Remove(session);
                return;
            }
            it->worker = worker;
            it->idle_since = Clock::now();
            // Keep most recently returned idle sessions at the back, without
            // allocating a second list or changing the ownership count.
            std::rotate(it, it + 1, entries.end());
        }

        void Prune() noexcept {
            const auto now = Clock::now();
            size_t retained_idle = 0;
            for (size_t i = entries.size(); i-- > 0;) {
                const auto& entry = entries[i];
                bool remove = false;
                if (entry.idle_since) {
                    if (retained_idle >= minimum_idle &&
                        now - *entry.idle_since >= idle_timeout) {
                        remove = true;
                    } else {
                        ++retained_idle;
                    }
                }
                if (remove) {
                    const auto closing = entry.session;
                    entries.erase(entries.begin() + static_cast<std::ptrdiff_t>(i));
                    Close(closing);
                }
            }
            StopIfEmpty();
        }

        void StopIfEmpty() noexcept {
            if (!entries.empty()) return;
            Cancel();
            memory::ThreadLocalVector<Entry>{entries.get_allocator()}.swap(entries);
        }

        void Schedule() {
            if (!ScheduleAfter(std::chrono::ceil<std::chrono::milliseconds>(check_interval),
                    domain ? domain->Reactor() : io_context))
                throw IoSystemError(io_error::operation_aborted);
        }

        void OnTimeout() noexcept override {
            // Pruning can drop the last indexed session and notify its users.
            // Keep this event's owner alive until rescheduling has finished.
            const auto self = this->shared_from_this();
            if (retired) return;
            try {
                Prune();
                if (!entries.empty()) Schedule();
            } catch (...) {
                failure = std::current_exception();
                Retire();
                try {
                    LOG_ERROR("AnyTLS outbound '{}': idle session scheduler failed", tag);
                } catch (...) {}
            }
        }

        void Retire() noexcept {
            retired = true;
            Cancel();
            memory::ThreadLocalVector<Entry> closing(entries.get_allocator());
            closing.swap(entries);
            for (const auto& entry : closing) Close(entry.session);
        }

        const std::shared_ptr<ExecutionDomain> domain;
        const net::any_io_executor executor;
        AwaitableTaskGroup& tasks;
        net::io_context& io_context;
        const Clock::duration check_interval;
        const Clock::duration idle_timeout;
        const size_t minimum_idle;
        const memory::ThreadLocalString tag;
        memory::ThreadLocalVector<Entry> entries;
        bool retired = false;
        std::exception_ptr failure;
    };

    const std::shared_ptr<State> state_;
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

    ~LogicalStreamLease() noexcept { Cleanup(ErrorCode::CANCELLED); }

    LogicalStreamLease(const LogicalStreamLease&) = delete;
    LogicalStreamLease& operator=(const LogicalStreamLease&) = delete;

    void Finish(ErrorCode error) noexcept {
        Cleanup(error);
        reusable = error == ErrorCode::OK && session->Available();
    }

private:
    void Cleanup(ErrorCode error) noexcept {
        if (cleaned) return;
        cleaned = true;
        session->UnregisterLogicalStream(sid);
        logical->Close(error);
        if (session->active_streams > 0) --session->active_streams;
    }
};
namespace {

net::awaitable<tl::expected<std::unique_ptr<AsyncStream>, ErrorCode>>
DialPhysicalSession(
    OutboundDialer& dialer,
    const Settings& settings,
    const OutboundDialer::OrderedBind* ordered_bind,
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
    const size_t auth_packet_size = 34 + static_cast<size_t>(auth_padding_size);
    std::array<uint8_t, 256> inline_auth{};
    memory::ByteVector heap_auth;
    struct CleanseAuthPacket {
        std::array<uint8_t, 256>& stack_buf;
        memory::ByteVector& heap_buf;
        ~CleanseAuthPacket() noexcept {
            OPENSSL_cleanse(stack_buf.data(), stack_buf.size());
            if (!heap_buf.empty()) {
                OPENSSL_cleanse(heap_buf.data(), heap_buf.size());
            }
        }
    } cleanse_auth_packet{inline_auth, heap_auth};
    uint8_t* auth_ptr = inline_auth.data();
    if (auth_packet_size > inline_auth.size()) {
        heap_auth.assign(auth_packet_size, uint8_t{0});
        auth_ptr = heap_auth.data();
    }
    std::copy(settings.password_hash.begin(), settings.password_hash.end(), auth_ptr);
    auth_ptr[32] = static_cast<uint8_t>(auth_padding_size >> 8);
    auth_ptr[33] = static_cast<uint8_t>(auth_padding_size);

    tl::expected<void, ErrorCode> ok;
    try {
        ok = co_await WriteAll(
            *new_stream,
            std::span<const uint8_t>(auth_ptr, auth_packet_size));
    } catch (...) {
        OPENSSL_cleanse(auth_ptr, auth_packet_size);
        new_stream->CloseAbortive();
        throw;
    }
    OPENSSL_cleanse(auth_ptr, auth_packet_size);
    if (!ok) {
        const bool timed_out =
            proxy::ConsumeOutboundHandshakeTimeout(*new_stream, deadline);
        new_stream->CloseAbortive();
        co_return tl::unexpected(timed_out ? ErrorCode::TIMEOUT : ok.error());
    }
    co_return std::move(new_stream);
}

tl::expected<memory::ByteVector, ErrorCode> BuildOpenPacket(
    uint32_t sid,
    bool is_udp,
    const TargetAddress& original_target,
    ForwardedMetadataView forwarded,
    const PaddingScheme* opening_scheme) {
    const TargetAddress stream_target = is_udp
        ? TargetAddress(proxy::uot::kMagicAddress, 0)
        : original_target;
    std::array<uint8_t, kMaxEncodedAddressSize> target{};
    const size_t target_size = (stream_target.IsValid() ||
        proxy::uot::VersionFromMagicAddress(stream_target))
        ? EncodeAddressTo(stream_target, target.data(), target.size(),
                          AddressWireFormat::Socks5, forwarded) : 0;
    if (target_size == 0) {
        return tl::unexpected(ErrorCode::INVALID_ARGUMENT);
    }

    memory::ByteVector packet;
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
        return tl::unexpected(ErrorCode::PROTOCOL_ENCODE_FAILED);
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
                 std::shared_ptr<const Settings> settings,
                 AwaitableTaskGroup& tasks)
    : tag_(tag)
    , settings_(std::move(settings))
    , padding_(AllocateWorkerShared<PaddingState>(io_context))
    , pool_(std::make_unique<SessionPool>(
          io_context, tasks, settings_->idle_session_check_interval,
          settings_->idle_session_timeout, settings_->min_idle_sessions, tag_)) {}

Handler::~Handler() noexcept = default;

net::awaitable<OutboundProcessResult> Handler::Process(
    session::Context& ctx,
    transport::Link inbound,
    OutboundDialer& dialer,
    const TimeoutsConfig& timeouts,
    StatsShard& stats,
    const RelayConfig& relay_config,
    buf::MultiBufferBatch first_payload,
    std::chrono::seconds relay_idle_timeout,
    std::chrono::seconds relay_write_timeout) {
    if (!inbound.Valid()) {
        co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }
    auto request = ExecutionDomain::Current();
    const auto ordered_bind = dialer.SelectOrderedBind(ctx);
    std::shared_ptr<const PaddingScheme> opening_scheme;
    uint32_t worker = 0;
    auto acquire = [&]() -> net::awaitable<SessionPool::Lease> {
        // This already-required pool control is the snapshot read boundary;
        // the handshake uses the returned immutable value, never an atomic.
        opening_scheme = padding_->scheme;
        co_return ordered_bind
            ? pool_->AcquireIf(worker, [&](const ClientSession& physical) {
                const auto& remote = physical.remote_endpoint;
                const auto& local = physical.local_endpoint;
                if (!remote || !local) return false;
                const auto& selected = remote->address().is_v6()
                    ? ordered_bind->v6 : ordered_bind->v4;
                return !selected.address ||
                    iputil::NormalizeAddress(local->address()) == *selected.address;
            })
            : pool_->Acquire(worker);
    };
    SessionPool::Lease transport_lease;
    std::shared_ptr<ClientSession> session;
    std::shared_ptr<ExecutionDomain> physical;
    bool attached = false;
    bool reusable = false;
    std::exception_ptr failure;
    OutboundProcessResult result = tl::unexpected(ErrorCode::INTERNAL);
    try {
        for (;;) {
            worker = request ? request->OwnerId() : 0;
            transport_lease = co_await net::co_spawn(
                pool_->Executor(), acquire(), net::use_awaitable);
            session = transport_lease.Get();
            physical = session ? session->domain : std::shared_ptr<ExecutionDomain>{};
            if (!session && request) {
                auto hooks = AllocateWorkerShared<PhysicalHooks>();
                physical = request->CreateSibling(hooks);
                hooks->allocation.SetLeaseGroup(
                    physical->LeaseIdentity(), &ExecutionDomain::SharesLeaseIdentity);
            }
            if (!request || !physical) break;
            attached = co_await request->AttachExclusive(physical);
            if (attached) break;
            // A receive-path handoff raced the host checkout. Never move the
            // healthy physical resource to satisfy this borrow; return it to
            // its existing Worker partition, then select on the new owner.
            transport_lease.Reuse();
            transport_lease = {};
            session.reset();
            physical.reset();
        }
        if (!session) {
            auto open = [&]() -> net::awaitable<tl::expected<std::shared_ptr<ClientSession>, ErrorCode>> {
                auto dialed = co_await DialPhysicalSession(dialer, *settings_,
                    ordered_bind ? &*ordered_bind : nullptr, timeouts.HandshakeTimeout(),
                    *opening_scheme, ctx);
                if (!dialed) co_return tl::unexpected(dialed.error());
                auto& io = physical ? physical->Reactor() : dialer.IoContext();
                auto* raw_session = new ClientSession(
                    io, std::move(*dialed), padding_, std::move(opening_scheme));
                memory::ScopedWorkerAllocation worker_allocation;
                co_return std::shared_ptr<ClientSession>(
                    raw_session,
                    [physical](ClientSession* value) noexcept {
                        if (!physical || physical->CanExecuteInline()) {
                            delete value;
                            return;
                        }
                        try {
                            physical->Execute([value] { delete value; });
                        } catch (...) {}
                    },
                    memory::ThreadLocalAllocator<ClientSession>{});
            };
            tl::expected<std::shared_ptr<ClientSession>, ErrorCode> opened =
                tl::unexpected(ErrorCode::INTERNAL);
            if (physical) {
                opened = co_await net::co_spawn(
                    physical->Executor(), open(), net::use_awaitable);
            } else {
                opened = co_await open();
            }
            if (!opened) {
                result = tl::unexpected(opened.error());
            } else {
                session = std::move(*opened);
                auto adopt = [&]() -> net::awaitable<SessionPool::Lease> {
                    co_return pool_->Adopt(session);
                };
                transport_lease = co_await net::co_spawn(
                    pool_->Executor(), adopt(), net::use_awaitable);
            }
        }
        if (session) {
            auto run = ProcessSession(ctx, inbound, dialer, timeouts, stats, relay_config,
                std::move(first_payload), relay_idle_timeout, relay_write_timeout, session, reusable);
            if (physical) {
                result = co_await net::co_spawn(
                    physical->Executor(), std::move(run), net::use_awaitable);
            } else {
                result = co_await std::move(run);
            }
        }
    } catch (...) {
        failure = std::current_exception();
    }
    // No lease can re-enter the idle index while its request domain is attached.
    // Cancellation of the request cannot strand the exclusive ownership edge.
    co_await net::this_coro::reset_cancellation_state(net::disable_cancellation());
    if (attached) co_await request->DetachExclusive(physical);
    if (reusable && !failure) transport_lease.Reuse();
    if (failure) std::rethrow_exception(failure);
    co_return result;
}

net::awaitable<OutboundProcessResult> Handler::ProcessSession(
    session::Context& ctx, transport::Link inbound, OutboundDialer& dialer,
    const TimeoutsConfig& timeouts, StatsShard& stats, const RelayConfig& relay_config,
    buf::MultiBufferBatch first_payload, std::chrono::seconds relay_idle_timeout,
    std::chrono::seconds relay_write_timeout,
    std::shared_ptr<ClientSession> session, bool& reusable) {
    auto& io_context = session->domain ? session->domain->Reactor() : dialer.IoContext();
    if (session->IsClosed()) co_return tl::unexpected(session->ClosedError());
    if (session->next_sid != 1) {
        LOG_CONN_DEBUG(ctx, "reusing idle session sid={}", session->next_sid);
        dialer.RecordConnected(ctx, *session->stream);
    }

    if (!session || !session->stream) {
        co_return tl::unexpected(ErrorCode::INTERNAL);
    }
    if (session->sid_exhausted) {
        co_return tl::unexpected(ErrorCode::RESOURCE_EXHAUSTED);
    }

    auto& stream = *session->stream;
    const uint32_t sid = session->AllocateSid();
    auto logical = session->RegisterLogicalStream(sid);
    LogicalStreamLease logical_lease(reusable, session, logical, sid);
    const bool is_udp = ctx.content.network == Network::UDP;
    const TargetAddress& original_target = ctx.outbound.target;
    auto open_logical_stream = [&]() -> net::awaitable<tl::expected<void, ErrorCode>> {
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
            const ErrorCode error = timed_out ? ErrorCode::TIMEOUT : ok.error();
            stream.Cancel();
            logical->Close(error);
            co_return tl::unexpected(error);
        }
        if (sid >= 2 && session->session_version == SessionVersion::V2) {
            if (auto ok = co_await logical->WaitOpenResult(kSynAckTimeout); !ok) {
                const bool timed_out =
                    proxy::ConsumeOutboundHandshakeTimeout(stream, deadline);
                const ErrorCode error = timed_out ? ErrorCode::TIMEOUT : ok.error();
                session->CloseAll(error);
                co_return tl::unexpected(error);
            }
        }
        co_return tl::expected<void, ErrorCode>{};
    };
    if (auto ok = co_await open_logical_stream(); !ok) {
        co_return tl::unexpected(ok.error());
    }
    // A pool lease exclusively owns this physical session for the request.
    // Its background reader must observe the same deadlines as relay writes.
    stream.SetIdleTimeout(relay_idle_timeout);
    stream.SetReadTimeout(std::chrono::seconds(0));
    stream.SetWriteTimeout(relay_write_timeout);
    stream.ClearPhaseDeadline();

    struct LogicalEndpoint final : transport::MultiBufferReader,
                                   transport::MultiBufferWriter {
        std::shared_ptr<ClientSession> session;
        std::shared_ptr<ClientSession::LogicalStream> logical;
        uint32_t sid = 0;
        bool is_udp = false;
        const TargetAddress& original_target;
        bool cancelled = false;
        size_t pending_writes = 0;

        struct PendingWrite {
            size_t& count;
            explicit PendingWrite(size_t& count) noexcept : count(count) { ++count; }
            ~PendingWrite() noexcept { --count; }
            PendingWrite(const PendingWrite&) = delete;
            PendingWrite& operator=(const PendingWrite&) = delete;
        };

        LogicalEndpoint(std::shared_ptr<ClientSession> s,
                        std::shared_ptr<ClientSession::LogicalStream> l,
                        uint32_t stream_id,
                        bool udp,
                        const TargetAddress& target)
            : session(std::move(s))
            , logical(std::move(l))
            , sid(stream_id)
            , is_udp(udp)
            , original_target(target) {}

        net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
            auto payload = co_await logical->ReadPayload();
            if (!payload) {
                if (payload.error() == ErrorCode::OK) {
                    co_return buf::MultiBuffer{};
                }
                throw transport::LinkError(payload.error());
            }
            if (is_udp) {
                for (auto* buffer : *payload) {
                    if (buffer && !buffer->IsEmpty()) {
                        buffer->SetUDP(original_target);
                    }
                }
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
                throw transport::LinkError(ErrorCode::CANCELLED);
            }
            logical->CheckWrite();

            PendingWrite pending(pending_writes);
            auto ok = co_await session->WritePayloadFrames(sid, *logical, std::move(mb));
            if (!ok) {
                logical->Close(ok.error());
                throw transport::LinkError(ok.error());
            }
        }

        net::awaitable<void> WriteBuffers(std::span<const net::const_buffer> buffers) override {
            if (cancelled) {
                throw transport::LinkError(ErrorCode::CANCELLED);
            }
            logical->CheckWrite();
            PendingWrite pending(pending_writes);
            auto ok = co_await session->WritePayloadBuffers(sid, *logical, buffers);
            if (!ok) {
                logical->Close(ok.error());
                throw transport::LinkError(ok.error());
            }
        }

        net::awaitable<void> AsyncShutdownWrite() override {
            if (!cancelled && logical->BeginLocalClose()) {
                PendingWrite pending(pending_writes);
                if (auto ok = co_await session->WriteFrameSerialized(kCmdFIN, sid, {}); !ok) {
                    throw transport::LinkError(ok.error());
                }
            }
        }

        transport::CancellationSource& Cancellation() noexcept override { return logical->Cancellation(); }

        void Cancel() noexcept {
            cancelled = true;
            logical->Close(ErrorCode::CANCELLED);
            // Relay also calls Cancel after a successful join. Preserve that
            // idle transport, but abort a pending gate/write: a partial frame
            // cannot safely be handed to the next request.
            if (pending_writes != 0) session->CloseAll(ErrorCode::CANCELLED);
        }

        void SetIdleTimeout(std::chrono::seconds timeout) {
            session->stream->SetIdleTimeout(timeout);
        }
        void SetReadTimeout(std::chrono::seconds timeout) {
            session->stream->SetReadTimeout(timeout);
        }
        void SetWriteTimeout(std::chrono::seconds timeout) {
            session->stream->SetWriteTimeout(timeout);
        }
        PhaseDeadlineHandle StartPhaseDeadline(std::chrono::seconds timeout) {
            return session->stream->StartPhaseDeadline(timeout);
        }
        void ClearPhaseDeadline() { session->stream->ClearPhaseDeadline(); }
        bool ConsumeIdleTimeout() noexcept { return session->stream->ConsumeIdleTimeout(); }
        bool ConsumeReadTimeout() noexcept { return session->stream->ConsumeReadTimeout(); }
        bool ConsumeWriteTimeout() noexcept { return session->stream->ConsumeWriteTimeout(); }
        bool ConsumePhaseDeadline() noexcept { return session->stream->ConsumePhaseDeadline(); }
    };

    LogicalEndpoint target_endpoint(
        session,
        logical,
        sid,
        is_udp,
        original_target);

    RelayResult result;
    auto relay_endpoint = [&](auto& endpoint) {
        return DoRelayLink(
            io_context, *inbound.reader, *inbound.writer, inbound.control,
            endpoint, ctx, stats, relay_config, std::move(first_payload));
    };

    if (is_udp) {
        proxy::uot::FramedEndpoint uot_endpoint(
            target_endpoint, true, original_target);
        result = co_await relay_endpoint(uot_endpoint);
    } else {
        result = co_await relay_endpoint(target_endpoint);
    }

    if (result.error == ErrorCode::OK) {
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
        auto settings = ::proxy::anytls::outbound::ParseSettings(cfg.settings);
        if (!settings) {
            LOG_ERROR("AnyTLS outbound '{}': invalid settings: {}",
                      cfg.tag, settings.error());
            return std::nullopt;
        }
        auto stream_settings = ::proxy::PrepareOutboundStream(
            cfg,
            settings->server,
            ::OutboundStreamDefaults{
                .require_tls = true,
                .fallback_server_name = {},
                .allow_insecure = false,
                .alpn = {},
            });
        using Settings = ::proxy::anytls::outbound::Settings;
        return ::proxyman::outbound::PreparedOutboundProxy{
            .create = ::proxyman::outbound::MakePreparedOutboundCreator<
                Settings,
                +[](std::string_view tag,
                    std::shared_ptr<const Settings> state,
                    ::net::io_context& io_context,
                    ::AwaitableTaskGroup& tasks) -> std::unique_ptr<::Outbound> {
                    return std::make_unique<::proxy::anytls::outbound::Handler>(
                        tag, io_context, std::move(state), tasks);
                }>(std::move(*settings), true),
            .sender = ::OutboundSenderSettings{
                .stream_settings = std::move(stream_settings),
                .send_through = {},
            },
        };
    }), true);
}  // namespace
