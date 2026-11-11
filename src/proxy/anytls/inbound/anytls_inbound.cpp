#include "proxy/inbound_admission.hpp"
#include "proxy/handshake_errors.hpp"
#include "app/relay.hpp"
#include "common/byte_reader.hpp"
#include "common/scoped_cleanse.hpp"
#include "common/awaitable_task_group.hpp"

#include "proxy/anytls/anytls_codec.hpp"
#include "proxy/anytls_padding.hpp"
#include "common/buf/length_prefixed_packet_buffer.hpp"
#include "proxy/uot/uot.hpp"
#include "transport/internet/async_write_gate.hpp"
#include "app/stats.hpp"
#include "app/rate_limiter.hpp"
#include "common/allocator.hpp"
#include "common/session.hpp"
#include "features/routing/dispatcher.hpp"
#include "infra/config_types.hpp"
#include "infra/log.hpp"
#include "app/proxyman/inbound/handler.hpp"
#include "transport/async_stream.hpp"
#include "transport/internet/timeout_scheduler.hpp"
#include "app/proxyman/inbound/user_store.hpp"
#include "common/address_codec.hpp"
#include "common/hash_container_shrink.hpp"

#include <asio/experimental/channel.hpp>
#include <openssl/crypto.h>
#include <algorithm>
#include <array>
#include <chrono>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <system_error>
#include <utility>

namespace proxy::anytls::inbound {


namespace {

constexpr size_t kMaxSubStreamQueuedPayloadBytes = proxy::anytls::kMaxFramePayload;
// Includes both pending headers and dispatched requests. At the per-stream
// queue limit this bounds queued application data to less than 8 MiB/session.
constexpr size_t kMaxConcurrentSubstreams = 128;

}  // namespace

Handler::Handler(const proxyman::inbound::AdmissionEnvironment& environment,
                 std::shared_ptr<const ::proxy::anytls::PaddingScheme> padding_scheme)
    : environment_(environment)
    , padding_scheme_(std::move(padding_scheme)) {}

namespace {


class AnyTLSDemuxSession;

class AnyTLSSubStream final
    : public transport::MultiBufferReader
    , public transport::MultiBufferWriter {
public:
    transport::CancellationSource& Cancellation() noexcept override { return cancellation_; }
    transport::EofAction ReadEofAction() const noexcept override { return transport::EofAction::CloseLink; }
    bool WriteShutdownClosesLink() const noexcept override { return true; }

    bool RemoteClosed() const noexcept { return remote_closed_; }
    bool IsClosed() const noexcept { return write_closed_; }

    void CheckWrite() const {
        if (cancelled_) throw transport::LinkError(common::ErrorCode::CANCELLED);
        if (write_closed_) throw transport::WriteClosed();
    }

    AnyTLSSubStream(net::io_context& io_context,
                    AnyTLSDemuxSession& session,
                    uint32_t sid)
        : input_signal_(net::any_io_executor(io_context.get_executor()), 1)
        , input_space_signal_(net::any_io_executor(io_context.get_executor()), 1)
        , session_(session)
        , sid_(sid) {}

    ~AnyTLSSubStream() noexcept override {
        Cancel();
    }

    AnyTLSSubStream(const AnyTLSSubStream&) = delete;
    AnyTLSSubStream& operator=(const AnyTLSSubStream&) = delete;

    [[nodiscard]] uint32_t Sid() const noexcept {
        return sid_;
    }

    session::Context ctx;

    net::awaitable<void> PushInput(buf::MultiBuffer mb) {
        const size_t bytes = mb.byte_size();
        if (cancelled_ || input_done_ || bytes == 0 ||
            bytes > kMaxSubStreamQueuedPayloadBytes) {
            mb.clear();
            co_return;
        }
        while (!cancelled_ &&
               !input_done_ &&
               queued_input_.byte_size() + bytes > kMaxSubStreamQueuedPayloadBytes) {
            auto [ec] = co_await input_space_signal_.async_receive(
                net::as_tuple(net::use_awaitable));
            if (ec) {
                mb.clear();
                co_return;
            }
        }
        if (cancelled_ || input_done_) {
            mb.clear();
            co_return;
        }
        buf::AppendCoalescedStreamInput(queued_input_, std::move(mb));
        WakeInputReader();
    }

    void CloseRemote() {
        remote_closed_ = true;
        write_closed_ = true;
        input_done_ = true;
        WakeInputReader();
        WakeInputWriter();
    }

    void Cancel() noexcept {
        if (cancelled_) {
            return;
        }
        cancelled_ = true;
        cancellation_.Stop();
        input_done_ = true;
        queued_input_.clear();
        WakeInputReader();
        WakeInputWriter();
    }

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
        while (!cancelled_) {
            if (!queued_input_.empty()) {
                auto input = std::move(queued_input_);
                queued_input_.ReleaseIfIdle();
                WakeInputWriter();
                co_return input;
            }
            queued_input_.ReleaseIfIdle();
            if (input_done_) {
                co_return buf::MultiBuffer{};
            }
            auto [ec] = co_await input_signal_.async_receive(
                net::as_tuple(net::use_awaitable));
            if (ec) {
                throw IoSystemError(
                    io_error::operation_aborted,
                    "AnyTLS substream input cancelled");
            }
        }
        throw IoSystemError(
            io_error::operation_aborted,
            "AnyTLS substream cancelled");
    }

    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer mb) override;
    net::awaitable<void> WriteBuffers(std::span<const net::const_buffer> buffers) override;
    net::awaitable<void> AsyncShutdownWrite() override;

private:
    transport::CancellationSource cancellation_;

    void WakeInputReader() noexcept {
        (void)input_signal_.try_send(IoErrorCode{});
    }

    void WakeInputWriter() noexcept {
        (void)input_space_signal_.try_send(IoErrorCode{});
    }

    common::SignalChannel input_signal_;
    common::SignalChannel input_space_signal_;
    AnyTLSDemuxSession& session_; // Run joins all users before destroying the session.
    uint32_t sid_ = 0;
    buf::MultiBuffer queued_input_;
    bool input_done_ = false;
    bool cancelled_ = false;
    bool write_closed_ = false;
    bool remote_closed_ = false;
};

class AnyTLSDemuxSession final {
public:
    AnyTLSDemuxSession(std::unique_ptr<transport::AsyncStream> stream,
                       routing::Dispatcher& dispatcher,
                       const routing::DispatchPolicy& policy,
                       const proxyman::inbound::AdmissionEnvironment& environment,
                       net::io_context& io_context,
                       const session::Context& session_ctx,
                       const infra::TimeoutsConfig& timeouts,
                       std::chrono::seconds control_idle_timeout,
                       const PaddingScheme* padding_scheme)
        : stream_(std::move(stream))
        , dispatcher_(dispatcher)
        , policy_(policy)
        , environment_(environment)
        , io_context_(io_context)
        , session_ctx_(session_ctx)
        , timeouts_(timeouts)
        , control_idle_timeout_(control_idle_timeout)
        , padding_scheme_(padding_scheme) {}

    ~AnyTLSDemuxSession() noexcept {
        CancelAll();
    }

    AnyTLSDemuxSession(const AnyTLSDemuxSession&) = delete;
    AnyTLSDemuxSession& operator=(const AnyTLSDemuxSession&) = delete;

    net::awaitable<app::RelayResult> Run();

    net::awaitable<tl::expected<void, common::ErrorCode>>
    WriteFrameSerialized(uint8_t cmd, uint32_t sid, std::span<const uint8_t> payload) {
        const auto sub = sid != 0 ? FindStream(sid) : nullptr;
        struct WriteCancelSubscription final : transport::CancellationSubscription {
            transport::internet::AsyncWriteGate& gate;
            transport::AsyncStream* stream = nullptr;
            net::cancellation_signal gate_cancel;
            bool writing = false;
            explicit WriteCancelSubscription(transport::internet::AsyncWriteGate& g) noexcept
                : gate(g) {}
            void OnCancellation(transport::Cancellation) noexcept override {
                if (!writing) gate_cancel.emit(net::cancellation_type::terminal);
                else if (stream) stream->Cancel();
            }
        } cancel_sub(write_gate_);
        if (cmd == proxy::anytls::kCmdSYNACK && sub) {
            cancel_sub.Resubscribe(sub->Cancellation());
        }
        auto write_lease = write_gate_.TryAcquire();
        if (!write_lease) {
            write_lease = co_await write_gate_.Acquire(
                false,
                (cmd == proxy::anytls::kCmdSYNACK && sub)
                    ? cancel_sub.gate_cancel.slot()
                    : net::cancellation_slot{});
        }
        if (!write_lease || cancelled_ || !stream_) {
            co_return tl::unexpected(common::ErrorCode::CONNECTION_CLOSED);
        }
        if (sub) {
            if (cmd == proxy::anytls::kCmdFIN && sub->RemoteClosed())
                co_return tl::expected<void, common::ErrorCode>{};
            if (cmd == proxy::anytls::kCmdSYNACK && (sub->IsClosed() || sub->Cancellation().Stopped()))
                co_return tl::unexpected(common::ErrorCode::CONNECTION_CLOSED);
        }
        if (cmd == proxy::anytls::kCmdSYNACK && sub) {
            cancel_sub.stream = stream_.get();
            cancel_sub.writing = true;
        }

        try {
            auto result = co_await proxy::anytls::WriteFrame(*stream_, cmd, sid, payload);
            if (!result) FailPhysicalWrite(result.error());
            co_return result;
        } catch (...) {
            FailPhysicalWrite(transport::ClassifyFailure(std::current_exception(), common::ErrorCode::INTERNAL));
            throw;
        }
    }

    net::awaitable<tl::expected<void, common::ErrorCode>>
    WriteMultiBufferSerialized(uint8_t cmd, uint32_t sid, buf::MultiBuffer mb) {
        auto write_lease = write_gate_.TryAcquire();
        if (!write_lease) write_lease = co_await write_gate_.Acquire();
        if (!write_lease || cancelled_ || !stream_) {
            mb.clear();
            co_return tl::unexpected(common::ErrorCode::CONNECTION_CLOSED);
        }
        CheckStreamWrite(sid);

        try {
            auto result = co_await proxy::anytls::WriteMultiBufferAsFrameBatch(
                *stream_, cmd, sid, std::move(mb));
            if (!result) FailPhysicalWrite(result.error());
            co_return result;
        } catch (...) {
            FailPhysicalWrite(transport::ClassifyFailure(std::current_exception(), common::ErrorCode::INTERNAL));
            throw;
        }
    }

    net::awaitable<tl::expected<void, common::ErrorCode>>
    WriteBuffersSerialized(uint8_t cmd,
                           uint32_t sid,
                           std::span<const net::const_buffer> buffers) {
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

        auto write_lease = write_gate_.TryAcquire();
        if (!write_lease) write_lease = co_await write_gate_.Acquire();
        if (!write_lease || cancelled_ || !stream_) {
            co_return tl::unexpected(common::ErrorCode::CONNECTION_CLOSED);
        }

        CheckStreamWrite(sid);
        try {
            auto result = co_await proxy::anytls::WriteBuffersAsFrameBatch(*stream_, cmd, sid, buffers);
            if (!result) FailPhysicalWrite(result.error());
            co_return result;
        } catch (...) {
            FailPhysicalWrite(transport::ClassifyFailure(std::current_exception(), common::ErrorCode::INTERNAL));
            throw;
        }
    }

    void RemoveStream(uint32_t sid) {
        auto it = streams_.find(sid);
        if (it == streams_.end()) {
            return;
        }
        auto sub = std::move(it->second);
        streams_.erase(it);
        common::MaybeShrinkHashContainer(streams_, 8);
        if (sub) {
            sub->Cancel();
        }
    }

private:
    void FailPhysicalWrite(common::ErrorCode error) noexcept {
        // A write completing after retirement only reports its consequences.
        // Preserve the frame loop's error (or clean EOF), not that drain error.
        if (cancelled_) return;
        physical_write_error_ = error;
        CancelAll();
    }
    std::shared_ptr<AnyTLSSubStream> FindStream(uint32_t sid) const {
        const auto it = streams_.find(sid);
        return it == streams_.end() ? nullptr : it->second;
    }

    void CheckStreamWrite(uint32_t sid) const {
        const auto it = streams_.find(sid);
        if (it == streams_.end() || !it->second) throw transport::WriteClosed();
        it->second->CheckWrite();
    }

    void CancelAll() noexcept {
        if (cancelled_) {
            return;
        }
        cancelled_ = true;
        write_gate_.Cancel();
        auto streams = std::exchange(
            streams_,
            memory::UnorderedMap<uint32_t, std::shared_ptr<AnyTLSSubStream>>{
                streams_.get_allocator()});
        for (auto& [sid, sub] : streams) {
            (void)sid;
            if (sub) {
                sub->Cancel();
            }
        }
        if (stream_) {
            stream_->CloseAbortive();
        }
    }

    net::awaitable<app::RelayResult> RejectSession(std::string_view message, common::ErrorCode error) {
        (void)co_await WriteFrameSerialized(proxy::anytls::kCmdAlert, 0,
            std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(message.data()), message.size()));
        app::RelayResult result;
        result.error = error;
        co_return result;
    }

    // Runs one header phase under the substream's absolute handshake budget.
    // The phase and its timer are joined before this returns; an expired
    // budget yields TIMEOUT even when the phase itself completed.
    template<class Phase>
    net::awaitable<common::ErrorCode> RunHandshakePhase(
        AnyTLSSubStream& sub, std::chrono::steady_clock::time_point opened_at, Phase& phase) {
        const auto deadline_tp = opened_at + timeouts_.HandshakeTimeout();
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline_tp) {
            sub.Cancel();
            co_return common::ErrorCode::TIMEOUT;
        }
        const auto remaining = std::chrono::ceil<std::chrono::milliseconds>(deadline_tp - now);
        bool timed_out = false;
        struct HandshakeDeadline final : transport::internet::TimeoutEvent {
            HandshakeDeadline(bool& timed_out, AnyTLSSubStream& sub) noexcept
                : timed_out(timed_out), sub(sub) {}
            void OnTimeout() override {
                timed_out = true;
                sub.Cancel();
            }
            bool& timed_out;
            AnyTLSSubStream& sub;
        } deadline(timed_out, sub);
        if (!transport::internet::TimeoutScheduler::ForIoContext(io_context_).ScheduleAfter(remaining, deadline))
            throw IoSystemError(io_error::operation_aborted);
        common::ErrorCode phase_error = common::ErrorCode::INTERNAL;
        try {
            phase_error = co_await phase();
        } catch (const IoSystemError&) {
            if (!timed_out) throw;
        }
        // Ready continuations can run before an already-due timer callback.
        // Do not dispatch a header that completed beyond its absolute budget.
        if (!timed_out && std::chrono::steady_clock::now() >= deadline_tp) {
            timed_out = true;
            sub.Cancel();
        }
        co_return timed_out ? common::ErrorCode::TIMEOUT : phase_error;
    }

    net::awaitable<common::ErrorCode> ProcessUdpSubstream(
        AnyTLSSubStream& sub,
        proxy::uot::Version uot_version,
        buf::MultiBuffer pending,
        std::chrono::steady_clock::time_point opened_at);
    net::awaitable<common::ErrorCode> ProcessStream(
        AnyTLSSubStream& sub, std::chrono::steady_clock::time_point opened_at);
    net::awaitable<void> RunStream(
        std::shared_ptr<AnyTLSSubStream> sub, std::chrono::steady_clock::time_point opened_at);
    net::awaitable<app::RelayResult> ReadClientSettings(const proxy::anytls::FrameHeader& header);
    net::awaitable<app::RelayResult> OpenClientStream(const proxy::anytls::FrameHeader& header, common::AwaitableTaskGroup& tasks);
    net::awaitable<app::RelayResult> ReadFrames(common::AwaitableTaskGroup& tasks);

    std::unique_ptr<transport::AsyncStream> stream_;
    routing::Dispatcher& dispatcher_;
    const routing::DispatchPolicy& policy_;
    const proxyman::inbound::AdmissionEnvironment& environment_;
    net::io_context& io_context_;
    const session::Context& session_ctx_;
    infra::TimeoutsConfig timeouts_;
    std::chrono::seconds control_idle_timeout_{};
    const PaddingScheme* padding_scheme_ = nullptr;
    transport::internet::AsyncWriteGate write_gate_;
    memory::UnorderedMap<uint32_t, std::shared_ptr<AnyTLSSubStream>> streams_;
    uint32_t last_stream_id_ = 0;
    bool cancelled_ = false;
    std::optional<common::ErrorCode> physical_write_error_;
    std::optional<proxy::anytls::SessionVersion> session_version_;
};

net::awaitable<void> AnyTLSSubStream::WriteMultiBuffer(buf::MultiBuffer mb) {
    CheckWrite();
    auto ok = co_await session_.WriteMultiBufferSerialized(proxy::anytls::kCmdPSH, sid_, std::move(mb));
    if (!ok) throw transport::LinkError(ok.error());
}

net::awaitable<void> AnyTLSSubStream::WriteBuffers(std::span<const net::const_buffer> buffers) {
    CheckWrite();
    auto ok = co_await session_.WriteBuffersSerialized(proxy::anytls::kCmdPSH, sid_, buffers);
    if (!ok) throw transport::LinkError(ok.error());
}

net::awaitable<void> AnyTLSSubStream::AsyncShutdownWrite() {
    if (write_closed_) co_return;
    write_closed_ = true;
    input_done_ = true;
    queued_input_.clear();
    WakeInputReader();
    WakeInputWriter();
    if (auto result = co_await session_.WriteFrameSerialized(proxy::anytls::kCmdFIN, sid_, {}); !result)
        throw transport::LinkError(result.error());
}

net::awaitable<common::ErrorCode> AnyTLSDemuxSession::ProcessUdpSubstream(
    AnyTLSSubStream& sub,
    proxy::uot::Version uot_version,
    buf::MultiBuffer pending,
    std::chrono::steady_clock::time_point opened_at) {
    std::optional<proxy::uot::PreparedRequest> prepared;
    auto read_header = [&]() -> net::awaitable<common::ErrorCode> {
        auto uot_header = co_await proxy::uot::ReadUotRequestHeader(
            uot_version, sub, std::move(pending));
        if (!uot_header) co_return uot_header.error();
        prepared.emplace(std::move(*uot_header));
        co_return common::ErrorCode::OK;
    };
    if (const auto error = co_await RunHandshakePhase(sub, opened_at, read_header);
        error != common::ErrorCode::OK) {
        co_return error;
    }
    if (sub.IsClosed()) co_return common::ErrorCode::CONNECTION_CLOSED;

    (void)co_await proxy::uot::DispatchPreparedUotRequest(
        std::move(*prepared), nullptr, sub, sub,
        dispatcher_, policy_, io_context_, sub.ctx, environment_.stats, timeouts_);
    co_return common::ErrorCode::OK;
}

net::awaitable<common::ErrorCode> AnyTLSDemuxSession::ProcessStream(
    AnyTLSSubStream& sub, std::chrono::steady_clock::time_point opened_at) {
    session::Context& ctx = sub.ctx;
    // Held for the stream's lifetime; a refusal ends only this stream.
    proxy::InboundSubstreamAdmission admission(environment_.stats);
    auto pending_admission = proxy::AdmitInboundSubstream(environment_, ctx);
    if (pending_admission &&
        !admission.Hold(co_await std::move(*pending_admission), ctx, environment_.stats)) {
        if (session_version_ == proxy::anytls::SessionVersion::V2) {
            constexpr std::string_view message = "connection rejected";
            (void)co_await WriteFrameSerialized(proxy::anytls::kCmdSYNACK, sub.Sid(),
                std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(message.data()), message.size()));
        }
        co_return common::ErrorCode::BLOCKED;
    }
    buf::MultiBuffer pending;
    std::optional<proxy::uot::Version> uot_version;
    auto prepare = [&]() -> net::awaitable<common::ErrorCode> {
        auto parsed = co_await common::ReadAddress(sub, pending, common::AddressWireFormat::Socks5,
                                           0,
                                           {.require_non_empty_domain = true,
                                            .allow_metadata = true});
        if (!parsed) co_return parsed.error();
        pending.DropPrefixBytes(parsed->consumed);
        uot_version = proxy::uot::VersionFromMagicAddress(parsed->target);
        if (!parsed->target.IsValid() && !uot_version) {
            co_return common::ErrorCode::PROTOCOL_INVALID_ADDRESS;
        }
        proxy::BindInboundRequestTarget(
            ctx,
            proxy::InboundRequestTarget{
                uot_version ? common::Network::UDP : common::Network::TCP,
                uot_version ? common::TargetAddress{} : std::move(parsed->target),
                std::move(parsed->forwarded)});
        if (session_version_ == proxy::anytls::SessionVersion::V2) {
            if (auto ok = co_await WriteFrameSerialized(proxy::anytls::kCmdSYNACK, sub.Sid(), {}); !ok)
                co_return ok.error();
        }
        co_return common::ErrorCode::OK;
    };

    if (const auto error = co_await RunHandshakePhase(sub, opened_at, prepare);
        error != common::ErrorCode::OK) {
        co_return error;
    }
    if (sub.IsClosed()) co_return common::ErrorCode::CONNECTION_CLOSED;
    // Header preparation is joined and its timer removed before Dispatcher.
    if (uot_version) {
        co_return co_await ProcessUdpSubstream(
            sub, *uot_version, std::move(pending), opened_at);
    }
    (void)co_await dispatcher_.Dispatch(io_context_, policy_, nullptr,
        transport::Link{&sub, &sub}, common::InitialPayload{std::move(pending)},
        ctx, environment_.stats, timeouts_);
    co_return common::ErrorCode::OK;
}

net::awaitable<void> AnyTLSDemuxSession::RunStream(
    std::shared_ptr<AnyTLSSubStream> sub, std::chrono::steady_clock::time_point opened_at) {
    common::ErrorCode error = common::ErrorCode::OK;
    try {
        error = co_await ProcessStream(*sub, opened_at);
    } catch (...) {
        error = transport::ClassifyFailure(std::current_exception(), common::ErrorCode::INTERNAL);
    }
    if (error == common::ErrorCode::CONNECTION_CLOSED && sub->RemoteClosed()) error = common::ErrorCode::OK;
    if (error != common::ErrorCode::OK) {
        LOG_CONN_DEBUG(sub->ctx, "stream sid={} ended > {}",
                       sub->Sid(), common::ErrorCodeToString(error));
    }
    // The request owner closes exactly once on every completion path. A remote
    // close is already terminal and produces no FIN reply. A failed FIN write
    // has already cancelled the whole physical session.
    try { co_await sub->AsyncShutdownWrite(); } catch (...) {}
    RemoveStream(sub->Sid());
}

net::awaitable<app::RelayResult> AnyTLSDemuxSession::Run() {
    app::RelayResult result;
    auto read_frames = [&](common::AwaitableTaskGroup& tasks) -> net::awaitable<void> {
        try {
            result = co_await ReadFrames(tasks);
        } catch (...) {
            CancelAll();
            throw; // The group records this failure before cancelling siblings.
        }
        CancelAll();
        // Join every logical task, including header preparation and async
        // cleanup, even when the frame loop returns normally.
        tasks.Cancel();
    };
    try {
        co_await common::RunAwaitableTaskGroup(co_await net::this_coro::executor,
            [&](common::AwaitableTaskGroup& tasks) { tasks.Spawn(read_frames(tasks)); });
    } catch (...) {
        if (!physical_write_error_) throw;
    }
    if (result.error == common::ErrorCode::SOCKET_EOF) result.error = common::ErrorCode::OK;
    if (physical_write_error_) result.error = *physical_write_error_;
    co_return result;
}

net::awaitable<app::RelayResult> AnyTLSDemuxSession::ReadClientSettings(const proxy::anytls::FrameHeader& header) {
    app::RelayResult result;
            if (header.sid != 0 || session_version_)
                co_return co_await RejectSession("invalid or repeated client settings", common::ErrorCode::PROTOCOL_INVALID_COMMAND);
            bool update_padding = false;
            std::optional<common::ErrorCode> settings_error;
            {
                auto text = co_await proxy::anytls::ReadFrameText(*stream_, header.length);
                if (!text) {
                    result.error = proxy::ResolveHandshakeReadFailure(*stream_, text.error());
                    co_return result;
                }
                auto parsed = proxy::anytls::ParsePeerSettings(*text);
                if (!parsed) {
                    settings_error = parsed.error();
                } else {
                    session_version_ = parsed->version; // Publish once before accepting any SYN.
                    update_padding = padding_scheme_ && !parsed->padding_md5.empty() &&
                        parsed->padding_md5 != padding_scheme_->Digest();
                }
            }
            if (settings_error)
                co_return co_await RejectSession("invalid client settings", *settings_error);
            stream_->ClearPhaseDeadline();
            stream_->SetIdleTimeout(control_idle_timeout_);
            if (session_version_ == proxy::anytls::SessionVersion::V2) {
                constexpr std::string_view kServerSettings = "v=2";
                if (auto ok = co_await WriteFrameSerialized(proxy::anytls::kCmdServerSettings, 0,
                        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(kServerSettings.data()), kServerSettings.size())); !ok) {
                    result.error = ok.error();
                    co_return result;
                }
            }
            if (update_padding) {
                if (auto ok = co_await WriteFrameSerialized(proxy::anytls::kCmdUpdatePaddingScheme, 0,
                        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(padding_scheme_->Raw().data()),
                            padding_scheme_->Raw().size())); !ok) {
                    result.error = ok.error();
                    co_return result;
                }
            }

    co_return result;
}

net::awaitable<app::RelayResult> AnyTLSDemuxSession::OpenClientStream(const proxy::anytls::FrameHeader& header, common::AwaitableTaskGroup& tasks) {
    app::RelayResult result;
    const auto sid = header.sid;
            std::string_view rejection;
            if (!session_version_) rejection = "client did not send its settings";
            else if (sid <= last_stream_id_) rejection = "stream IDs must increase";
            else if (header.length != 0) rejection = "SYN must not carry data";
            if (!rejection.empty())
                co_return co_await RejectSession(rejection, common::ErrorCode::PROTOCOL_INVALID_COMMAND);
            if (streams_.size() >= kMaxConcurrentSubstreams) {
                proxy::LogInboundRequestRejected(session_ctx_, "concurrent stream limit");
                last_stream_id_ = sid; // A refused ID is retired, never reusable.
                environment_.stats.OnError();
                if (session_version_ == proxy::anytls::SessionVersion::V2) {
                    constexpr std::string_view message = "concurrent stream limit";
                    auto ok = co_await WriteFrameSerialized(proxy::anytls::kCmdSYNACK, sid,
                        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(message.data()), message.size()));
                    if (!ok) { result.error = ok.error(); co_return result; }
                }
                if (auto ok = co_await WriteFrameSerialized(proxy::anytls::kCmdFIN, sid, {}); !ok) {
                    result.error = ok.error();
                    co_return result;
                }
                co_return result;
            }
            const auto opened_at = std::chrono::steady_clock::now();
            auto sub = std::make_shared<AnyTLSSubStream>(io_context_, *this, sid);
            sub->ctx.InitSubstreamFrom(session_ctx_);
            sub->ctx.content.network = common::Network::TCP;
            streams_.emplace(sid, sub);
            last_stream_id_ = sid; // Commit after the complete stream was inserted.
            tasks.Spawn(RunStream(std::move(sub), opened_at));

    co_return result;
}

net::awaitable<app::RelayResult> AnyTLSDemuxSession::ReadFrames(common::AwaitableTaskGroup& tasks) {
    app::RelayResult result;
    auto resolve_handshake_error = [&](common::ErrorCode error) noexcept {
        return !session_version_
            ? proxy::ResolveHandshakeReadFailure(*stream_, error)
            : error;
    };
    while (!cancelled_) {
        auto header = co_await proxy::anytls::ReadFrameHeader(*stream_);
        if (!header) {
            result.error = resolve_handshake_error(header.error());
            break;
        }

        if (header->cmd == proxy::anytls::kCmdSettings) {
            auto settings = co_await ReadClientSettings(*header);
            if (!settings.Ok()) co_return settings;
            continue;
        }
        if (header->cmd == proxy::anytls::kCmdServerSettings || header->cmd == proxy::anytls::kCmdUpdatePaddingScheme ||
            header->cmd == proxy::anytls::kCmdSYNACK)
            co_return co_await RejectSession("server command received from client", common::ErrorCode::PROTOCOL_INVALID_COMMAND);
        if (header->cmd == proxy::anytls::kCmdHeartRequest || header->cmd == proxy::anytls::kCmdHeartResponse) {
            if (session_version_ != proxy::anytls::SessionVersion::V2 || header->sid != 0 || header->length != 0)
                co_return co_await RejectSession("heartbeat requires negotiated v2", common::ErrorCode::PROTOCOL_INVALID_COMMAND);
            if (header->cmd == proxy::anytls::kCmdHeartRequest) {
                if (auto ok = co_await WriteFrameSerialized(proxy::anytls::kCmdHeartResponse, 0, {}); !ok) {
                    result.error = ok.error();
                    break;
                }
            }
            continue;
        }
        if (header->cmd == proxy::anytls::kCmdWaste) {
            if (auto ok = co_await proxy::anytls::DiscardFramePayload(*stream_, header->length); !ok) {
                result.error = resolve_handshake_error(ok.error());
                break;
            }
            continue;
        }

        const uint32_t sid = header->sid;
        if (header->cmd == proxy::anytls::kCmdSYN) {
            auto opened = co_await OpenClientStream(*header, tasks);
            if (!opened.Ok()) co_return opened;
            continue;
        }
        if ((header->cmd != proxy::anytls::kCmdFIN && header->cmd != proxy::anytls::kCmdPSH) ||
            sid == 0 || sid > last_stream_id_) {
            if (auto ok = co_await proxy::anytls::DiscardFramePayload(*stream_, header->length); !ok) {
                result.error = ok.error();
                break;
            }
            result.error = common::ErrorCode::PROTOCOL_INVALID_COMMAND;
            break;
        }

        // The dispatcher can retire this stream during any following await.
        // Retain the stream itself, never an iterator into the live index.
        const auto sub = FindStream(sid);
        if (!sub || header->cmd == proxy::anytls::kCmdFIN || sub->IsClosed()) {
            if (auto ok = co_await proxy::anytls::DiscardFramePayload(*stream_, header->length); !ok) {
                result.error = ok.error();
                break;
            }
            if (sub && header->cmd == proxy::anytls::kCmdFIN) {
                sub->CloseRemote();
            }
            continue;
        }

        auto payload = co_await proxy::anytls::ReadFramePayload(*stream_, header->length);
        if (!payload) {
            result.error = payload.error();
            break;
        }

        co_await sub->PushInput(std::move(*payload));
    }

    co_return result;
}

net::awaitable<tl::expected<void, common::ErrorCode>> ReadAuth(
    transport::AsyncStream& stream,
    std::array<uint8_t, 32>& hash) {

    std::array<uint8_t, ::proxy::anytls::kAuthPrefixSize> auth{};
    common::ScopedCleanse cleanse_auth{auth};
    auto read = co_await proxy::ReadHandshakeExact(
        stream, auth, proxy::HandshakeProgress::NotStarted);
    if (!read) co_return tl::unexpected(read.error());
    std::copy_n(auth.begin(), hash.size(), hash.begin());
    const uint16_t padding = common::LoadU16BE(&auth[32]);
    OPENSSL_cleanse(auth.data(), auth.size());
    if (auto ok = co_await proxy::anytls::DiscardFramePayload(stream, padding); !ok) {
        co_return tl::unexpected(
            proxy::ResolveHandshakeReadFailure(stream, ok.error()));
    }
    co_return tl::expected<void, common::ErrorCode>{};
}

net::awaitable<tl::expected<common::UserOnlineSessionGuard, common::ErrorCode>>
AuthenticateSession(
    transport::AsyncStream& stream,
    proxy::InboundAuthentication authentication,
    session::Context& ctx,
    const infra::TimeoutsConfig& timeouts,
    std::chrono::seconds control_idle_timeout) {
    std::array<uint8_t, 32> auth_hash{};
    common::ScopedCleanse cleanse_hash{auth_hash};
    if (auto ok = co_await ReadAuth(stream, auth_hash); !ok) {
        co_return tl::unexpected(ok.error());
    }
    const auto credential = co_await authentication.VerifyCredential({proxy::KeyedInboundProtocol::AnyTls, auth_hash});
    if (credential != common::ErrorCode::OK) co_return tl::unexpected(credential);
    auto user = proxyman::inbound::UserStore::FindAnyTlsUser(ctx.inbound.tag, auth_hash);
    OPENSSL_cleanse(auth_hash.data(), auth_hash.size());
    if (!user) co_return tl::unexpected(co_await authentication.RejectCredential("no matching credential"));
    stream.SetReadTimeout(std::chrono::seconds(0));
    stream.SetWriteTimeout(
        std::min(timeouts.WriteTimeout(), control_idle_timeout));

    // Session-level authentication: no target exists until streams open.
    auto user_session = co_await proxy::AuthenticateAndAdmit(
        std::move(authentication), &user->profile, "no matching credential", std::nullopt);
    if (!user_session) co_return tl::unexpected(user_session.error());

    // Metadata is owned by ctx; authentication must not pin an old user table
    // for the lifetime of this control transport and all its logical streams.
    user.reset();
    ctx.content.network = common::Network::MUX;
    co_return std::move(*user_session);
}

}  // namespace

net::awaitable<app::RelayResult>
Handler::Process(
    std::unique_ptr<transport::AsyncStream> stream,
    routing::Dispatcher& dispatcher,
    const proxyman::inbound::ReceiverSettings& receiver,
    net::io_context& io_context,
    session::Context& ctx,
    const infra::TimeoutsConfig& timeouts,
    uint32_t pressure_idle_timeout) {
    if (!stream) {
        app::RelayResult result;
        result.error = common::ErrorCode::PROTOCOL_DECODE_FAILED;
        co_return result;
    }

    try {
        auto authentication = co_await proxy::BeginInboundAuthentication(environment_, ctx);
        if (!authentication) co_return proxy::RejectInbound(environment_.stats, stream.get(), authentication.error());

        auto control_idle_timeout = timeouts.IdleTimeout();
        if (pressure_idle_timeout > 0) {
            control_idle_timeout = std::min(
                control_idle_timeout,
                std::chrono::seconds(pressure_idle_timeout));
        }

        common::UserOnlineSessionGuard user_session;
        {
            auto auth = co_await AuthenticateSession(
                *stream, std::move(*authentication), ctx, timeouts, control_idle_timeout);
            if (!auth) {
                co_return proxy::RejectInbound(environment_.stats, stream.get(), auth.error());
            }
            user_session = std::move(*auth);
        }
        AnyTLSDemuxSession demux(
            std::move(stream),
            dispatcher,
            receiver.dispatch_policy,
            environment_,
            io_context,
            ctx,
            timeouts,
            control_idle_timeout,
            padding_scheme_.get());
        co_return co_await demux.Run();
    } catch (...) {
        co_return proxy::RejectInbound(
            environment_.stats, stream.get(),
            transport::ClassifyFailure(std::current_exception(), common::ErrorCode::INTERNAL));
    }
}

}  // namespace proxy::anytls::inbound

namespace {
class AnyTlsSettings final
    : public ::proxyman::inbound::ProtocolSettings {
public:
    std::shared_ptr<const ::proxy::anytls::PaddingScheme> padding_scheme;
};

[[nodiscard]] const AnyTlsSettings* GetAnyTlsSettings(
    const ::proxyman::inbound::BuildRequest& req) noexcept {
    return dynamic_cast<const AnyTlsSettings*>(req.settings.get());
}

const bool kInboundRegistered = [] {
    ::proxyman::inbound::ProxyRegistration reg;
    reg.user_protocol = ::proxyman::inbound::UserProtocol::AnyTls;
    reg.traits = {.mailbox_email_defaults_to_tag = true, .requires_tls = true};


    reg.create_tcp_handler =
        [](const ::proxyman::inbound::AdmissionEnvironment& environment,
           const ::proxyman::inbound::BuildRequest& req) -> std::unique_ptr<::proxy::Inbound> {
            const auto* settings = GetAnyTlsSettings(req);
            if (!settings) {
                return nullptr;
            }
            return std::make_unique<::proxy::anytls::inbound::Handler>(
                environment,
                settings->padding_scheme);
        };

    reg.prepare_settings =
        [](std::string_view tag, const ::infra::InboundProtocolSettings& config)
            -> std::optional<std::shared_ptr<
                const ::proxyman::inbound::ProtocolSettings>> {
            // Text was validated (size and grammar) by infra::ParseAnyTlsPaddingScheme;
            // this only builds the runtime scheme object.
            auto settings = std::make_shared<AnyTlsSettings>();
            if (!config.padding_scheme.empty()) {
                auto parsed =
                    ::proxy::anytls::ParsePaddingScheme(config.padding_scheme);
                if (!parsed) {
                    LOG_WARN(
                        "AnyTLS inbound '{}': invalid padding scheme", tag);
                    return std::nullopt;
                }
                settings->padding_scheme =
                    std::make_shared<const ::proxy::anytls::PaddingScheme>(std::move(*parsed));
            }
            return settings;
        };

    reg.build_users =
        [](const ::proxyman::inbound::BuildRequest& req,
           std::span<const ::infra::InboundUserSpec> specs) {
            return ::proxy::BuildHashedInboundUsers<
                ::proxyman::inbound::PreparedAnyTlsUser>(
                "AnyTLS", req, specs,
                [](auto& info, std::string_view credential) {
                    info.password_hash = ::proxy::anytls::PasswordHash(credential);
                });
        };

    ::proxyman::inbound::RegisterProxy(
        ::constants::protocol::kAnyTLS, std::move(reg));
    return true;
}();
}  // namespace
